import socket
import json
import threading
import sys
import time
import base64
import os

from crypto_utils import (
    ensure_sign_keypair, pub_x25519_to_b64, b64_to_x25519_pub,
    sign_ed25519, verify_ed25519, pub_ed25519_to_pem, load_ed25519_pub_from_pem
)
from crypto_utils import gen_x25519
from double_ratchet import DoubleRatchet

HOST = '127.0.0.1'
PORT = 8888

def send_json_line(sock, obj):
    sock.sendall((json.dumps(obj) + '\n').encode())

def recv_lines(sock):
    buf = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            if buf:
                yield buf.decode()
            break
        buf += chunk
        while b'\n' in buf:
            line, buf = buf.split(b'\n', 1)
            yield line.decode()

sign_priv, sign_pub, sign_pub_pem = ensure_sign_keypair("alice")

peer_pub_path = "bob_sign_pub.pem"
peer_pub = None
if os.path.exists(peer_pub_path):
    with open(peer_pub_path, "rb") as f:
        peer_pem = f.read()
    peer_pub = load_ed25519_pub_from_pem(peer_pem)
    print("[INFO] Loaded Bob's long-term public key for mutual auth.")

dh_sk, dh_pk = gen_x25519()

sock = socket.socket()
try:
    sock.connect((HOST, PORT))
except ConnectionRefusedError:
    print("[FATAL] Cannot connect to Bob. Ensure Bob is running.")
    sys.exit(1)
print("[INFO] Connected to Bob")

dh_pub_b64 = pub_x25519_to_b64(dh_pk)
sign_pub_pem_b64 = base64.b64encode(sign_pub_pem).decode()
dh_raw = base64.b64decode(dh_pub_b64)
sig_b64 = sign_ed25519(sign_priv, dh_raw)
handshake = [dh_pub_b64, sign_pub_pem_b64, sig_b64]
send_json_line(sock, handshake)

lines = recv_lines(sock)
try:
    line = next(lines)
except StopIteration:
    print("[FATAL] No handshake response from Bob"); sock.close(); sys.exit(1)

try:
    resp = json.loads(line)
except Exception as e:
    print("[FATAL] Bad handshake response:", e); sock.close(); sys.exit(1)

if not (isinstance(resp, list) and len(resp) == 3):
    print("[FATAL] Bad handshake structure"); sock.close(); sys.exit(1)

bob_dh_b64, bob_sign_pem_b64, bob_sig_b64 = resp
bob_dh_raw = base64.b64decode(bob_dh_b64)
bob_sign_pem = base64.b64decode(bob_sign_pem_b64)
bob_sign_pub = load_ed25519_pub_from_pem(bob_sign_pem)

ok = verify_ed25519(bob_sign_pub, bob_dh_raw, bob_sig_b64)
if not ok:
    print("[FATAL] Bob signature verification on DH pub FAILED! Possible MITM."); sock.close(); sys.exit(1)

if peer_pub:
    if bob_sign_pem != pub_ed25519_to_pem(peer_pub):
        print("[FATAL] Bob's presented long-term public key differs from pre-shared one! Abort."); sock.close(); sys.exit(1)
    else:
        print("[INFO] Bob identity matches pre-shared public key.")
else:
    with open("bob_sign_pub.pem", "wb") as f:
        f.write(bob_sign_pem)
    print("[NOTE] Bob's public key saved as bob_sign_pub.pem (TOFU). For strict mutual-auth, pre-share keys and replace this file.")

print("[INFO] Verified Bob signature on DH pub")

bob_dh_pub = b64_to_x25519_pub(bob_dh_b64)
shared = dh_sk.exchange(bob_dh_pub)
dr = DoubleRatchet(root_key=shared, dh_sk=dh_sk, dh_pk=dh_pk, peer_dh_pk=bob_dh_pub)
print("[INFO] Ready. Type messages. Type /ratchet to rotate ephemeral DH locally.")

def recv_thread():
    for ln in lines:
        if not ln:
            continue
        try:
            payload = json.loads(ln)
        except Exception:
            continue
        try:
            pt = dr.receive_message(payload)
        except Exception as e:
            print("\n[ERROR] Decrypt/validation failed:", e)
            print(">>> ", end="", flush=True)
            continue
        print("\n<<<", pt)
        print(">>> ", end="", flush=True)

t = threading.Thread(target=recv_thread, daemon=True)
t.start()

try:
    while True:
        line = input(">>> ")
        if not line:
            continue
        if line.strip() == "/ratchet":
            new_sk, new_pk = gen_x25519()
            dh_sk = new_sk; dh_pk = new_pk
            dr.perform_local_ratchet(new_sk, new_pk)
            print("[INFO] Performed local ephemeral DH rotation (next outgoing messages will include new ratchet_pub).")
            continue
        out = dr.encrypt_message(line)
        send_json_line(sock, out)
        time.sleep(0.01)
except (KeyboardInterrupt, EOFError):
    print("\n[INFO] Exiting")
finally:
    sock.close()
    sys.exit(0)
