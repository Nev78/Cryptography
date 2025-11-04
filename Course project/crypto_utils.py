
import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def gen_x25519() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    sk = x25519.X25519PrivateKey.generate()
    return sk, sk.public_key()

def gen_ed25519() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk, sk.public_key()

def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes = b'ratchet', length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

def derive_root_and_chain(root_key: bytes, dh_shared: bytes) -> Tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=root_key, info=b'root_chain').derive(dh_shared)
    return okm[:32], okm[32:]

def derive_message_key(chain_key: bytes) -> Tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'chain_step').derive(chain_key)
    return okm[:32], okm[32:]  

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b'') -> Tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return ct, nonce

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b'') -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)

def pub_x25519_to_b64(pub: x25519.X25519PublicKey) -> str:
    return base64.b64encode(pub.public_bytes(encoding=serialization.Encoding.Raw,
                                             format=serialization.PublicFormat.Raw)).decode()

def b64_to_x25519_pub(s: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(base64.b64decode(s))

def sign_ed25519(priv: ed25519.Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(priv.sign(data)).decode()

def verify_ed25519(pub: ed25519.Ed25519PublicKey, data: bytes, sig_b64: str) -> bool:
    try:
        pub.verify(base64.b64decode(sig_b64), data)
        return True
    except Exception:
        return False

def pub_ed25519_to_pem(pub: ed25519.Ed25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def priv_ed25519_to_pem(priv: ed25519.Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(encoding=serialization.Encoding.PEM,
                              format=serialization.PrivateFormat.PKCS8,
                              encryption_algorithm=serialization.NoEncryption())

def load_ed25519_pub_from_pem(pem_bytes: bytes) -> ed25519.Ed25519PublicKey:
    return serialization.load_pem_public_key(pem_bytes)

def load_ed25519_priv_from_pem(pem_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem_bytes, password=None)

def ensure_sign_keypair(identity: str):
    priv_path = f"{identity}_sign_priv.pem"
    pub_path = f"{identity}_sign_pub.pem"
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv_pem = f.read()
        with open(pub_path, "rb") as f:
            pub_pem = f.read()
        priv = load_ed25519_priv_from_pem(priv_pem)
        pub = load_ed25519_pub_from_pem(pub_pem)
        return priv, pub, pub_pem
    else:
        priv, pub = gen_ed25519()
        priv_pem = priv_ed25519_to_pem(priv)
        pub_pem = pub_ed25519_to_pem(pub)
        with open(priv_path, "wb") as f:
            f.write(priv_pem)
        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        return priv, pub, pub_pem
