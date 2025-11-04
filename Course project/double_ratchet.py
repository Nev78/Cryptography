
import base64
import time
import hashlib
from typing import Dict, Tuple
from crypto_utils import derive_message_key, derive_root_and_chain, aead_encrypt, aead_decrypt, pub_x25519_to_b64, b64_to_x25519_pub
from cryptography.hazmat.primitives.asymmetric import x25519

MAX_SKIP = 256
MAX_TIMESTAMP_SKEW = 300        
MAX_STORED_MESSAGE_IDS = 10000


def make_message_id(ratchet_pub_b64: str, msg_num: int, timestamp: int, nonce: bytes, ct: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(ratchet_pub_b64.encode())
    h.update(msg_num.to_bytes(8, 'big'))
    h.update(int(timestamp).to_bytes(8, 'big'))
    h.update(nonce)
    h.update(ct)
    return h.digest()


class DoubleRatchet:
    def __init__(self, root_key: bytes, dh_sk: x25519.X25519PrivateKey, dh_pk: x25519.X25519PublicKey, peer_dh_pk: x25519.X25519PublicKey):
        self.root_key = root_key
        self.dh_sk = dh_sk
        self.dh_pk = dh_pk
        self.peer_dh_pk = peer_dh_pk

        _, chain = derive_root_and_chain(self.root_key, self.dh_sk.exchange(self.peer_dh_pk))
        self.chain_key_send = chain
        self.chain_key_recv = chain

        self.send_count = 0
        self.recv_count = 0

        self.skipped_message_keys: Dict[str, bytes] = {}

        self.seen_message_ids: Dict[bytes, int] = {}
        self.last_recv_msgnum_for_pub: Dict[str, int] = {}

    def _prune_seen_ids(self):
        if len(self.seen_message_ids) <= MAX_STORED_MESSAGE_IDS:
            return
        items = sorted(self.seen_message_ids.items(), key=lambda kv: kv[1])
        to_remove = len(self.seen_message_ids) - MAX_STORED_MESSAGE_IDS
        for i in range(to_remove):
            k, _ = items[i]
            self.seen_message_ids.pop(k, None)

    def perform_local_ratchet(self, new_dh_sk: x25519.X25519PrivateKey, new_dh_pk: x25519.X25519PublicKey):
        
        self.dh_sk = new_dh_sk
        self.dh_pk = new_dh_pk

        
        try:
            shared = self.dh_sk.exchange(self.peer_dh_pk)
        except Exception:
            return

        self.root_key, new_chain = derive_root_and_chain(self.root_key, shared)
        self.chain_key_send = new_chain
        self.chain_key_recv = new_chain
        self.skipped_message_keys.clear()
        self.send_count = 0
        self.recv_count = 0

    def _do_local_dh_rotate_and_derive(self):
        new_sk = x25519.X25519PrivateKey.generate()
        new_pk = new_sk.public_key()
        self.perform_local_ratchet(new_sk, new_pk)
        return new_pk

    def encrypt_message(self, plaintext: str) -> list:
        new_pk = self._do_local_dh_rotate_and_derive()
        self.chain_key_send, mk = derive_message_key(self.chain_key_send)
        self.send_count += 1
        ts = int(time.time())
        ct, nonce = aead_encrypt(mk, plaintext.encode())

        return [
            base64.b64encode(ct).decode(),
            base64.b64encode(nonce).decode(),
            pub_x25519_to_b64(self.dh_pk),
            self.send_count,
            ts
        ]

    def receive_message(self, payload_list: list) -> str:
        if not isinstance(payload_list, list) or len(payload_list) != 5:
            raise ValueError("Bad payload format")

        ct = base64.b64decode(payload_list[0])
        nonce = base64.b64decode(payload_list[1])
        peer_ratchet_b64 = payload_list[2]
        peer_msg_num = int(payload_list[3])
        peer_ts = int(payload_list[4])

        now = int(time.time())
        if abs(now - peer_ts) > MAX_TIMESTAMP_SKEW:
            raise ValueError("Timestamp skew too large")

        msg_id = make_message_id(peer_ratchet_b64, peer_msg_num, peer_ts, nonce, ct)
        if msg_id in self.seen_message_ids:
            raise ValueError("Replay detected (message_id seen)")

        current_peer_pub_b64 = pub_x25519_to_b64(self.peer_dh_pk)
        if peer_ratchet_b64 != current_peer_pub_b64:
            new_peer_pub = b64_to_x25519_pub(peer_ratchet_b64)
            shared = self.dh_sk.exchange(new_peer_pub)
            self.root_key, new_chain = derive_root_and_chain(self.root_key, shared)
            self.chain_key_recv = new_chain
            self.chain_key_send = new_chain
            self.peer_dh_pk = new_peer_pub
            self.recv_count = 0
            self.skipped_message_keys.clear()
            self.last_recv_msgnum_for_pub[peer_ratchet_b64] = 0

        last_seen = self.last_recv_msgnum_for_pub.get(peer_ratchet_b64, 0)
        if peer_msg_num <= last_seen:
            raise ValueError("Message number not greater than last seen (possible replay/reorder)")

        expected = self.recv_count + 1
        if peer_msg_num > expected:
            gap = peer_msg_num - expected
            if gap > MAX_SKIP:
                raise ValueError("Too many skipped messages")
            for i in range(expected, peer_msg_num):
                self.chain_key_recv, mk_skip = derive_message_key(self.chain_key_recv)
                key_id = f"{pub_x25519_to_b64(self.peer_dh_pk)}:{i}"
                self.skipped_message_keys[key_id] = mk_skip

        key_id_this = f"{pub_x25519_to_b64(self.peer_dh_pk)}:{peer_msg_num}"
        if key_id_this in self.skipped_message_keys:
            mk_recv = self.skipped_message_keys.pop(key_id_this)
        else:
            self.chain_key_recv, mk_recv = derive_message_key(self.chain_key_recv)

        try:
            plaintext = aead_decrypt(mk_recv, nonce, ct).decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

        self.seen_message_ids[msg_id] = peer_ts
        self.last_recv_msgnum_for_pub[peer_ratchet_b64] = peer_msg_num
        self.recv_count = peer_msg_num

        if len(self.seen_message_ids) > MAX_STORED_MESSAGE_IDS:
            self._prune_seen_ids()

        try:
            del mk_recv
        except Exception:
            pass

        return plaintext
