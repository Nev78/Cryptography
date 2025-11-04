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

HOST = '0.0.0.0'
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

sign_priv, sign_pub, sign_pub_pem = ensure_sign_keypair("bob")

peer_pub_path = "alice_sign_pub.pem"
peer_pub = None
if os.path.exists(peer_pub_path):
    with open(peer_pub_path, "rb") as f:
        peer_pem = f.read()
    peer_pub = load_ed25519_pub_from_pem(peer_pem)
    print("[INFO] Loaded Alice's long-term public key for mutual auth.")

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, PORT))
srv.listen(1)
print("[INFO] Listening...")
conn, addr = srv.accept()
print("[INFO] Connected by", addr)

lines = recv_lines(conn)

try:
    ln = next(lines)
except StopIteration:
    print("[FATAL] No handshake from client"); conn.close(); srv.close(); sys.exit(1)

try:
    hand = json.loads(ln)
except Exception as e:
    print("[FATAL] Bad handshake JSON:", e); conn.close(); srv.close(); sys.exit(1)

if not (isinstance(hand, list) and len(hand) == 3):
    print("[FATAL] Bad handshake structure"); conn.close(); srv.close(); sys.exit(1)

alice_dh_b64, alice_sign_pem_b64, alice_sig_b64 = hand
alice_dh_raw = base64.b64decode(alice_dh_b64)
alice_sign_pem = base64.b64decode(alice_sign_pem_b64)
alice_sign_pub = load_ed25519_pub_from_pem(alice_sign_pem)

if not verify_ed25519(alice_sign_pub, alice_dh_raw, alice_sig_b64):
    print("[FATAL] Alice signature verification failed!"); conn.close(); srv.close(); sys.exit(1)

if peer_pub:
    if alice_sign_pem != pub_ed25519_to_pem(peer_pub):
        print("[FATAL] Alice's presented pub differs from pre-shared one! Abort."); conn.close(); srv.close(); sys.exit(1)
    else:
        print("[INFO] Alice identity matches pre-shared public key.")
else:
    with open("alice_sign_pub.pem", "wb") as f:
        f.write(alice_sign_pem)
    print("[NOTE] Alice public key saved as alice_sign_pub.pem (TOFU). For strict mutual-auth, pre-share keys.")

print("[INFO] Verified Alice signature on DH pub")

dh_sk, dh_pk = gen_x25519()
dh_pub_b64 = pub_x25519_to_b64(dh_pk)
sign_pub_pem_b64 = base64.b64encode(sign_pub_pem).decode()
dh_raw = base64.b64decode(dh_pub_b64)
sig_b64 = sign_ed25519(sign_priv, dh_raw)
resp = [dh_pub_b64, sign_pub_pem_b64, sig_b64]
send_json_line(conn, resp)

alice_dh_pub = b64_to_x25519_pub(alice_dh_b64)
shared = dh_sk.exchange(alice_dh_pub)
dr = DoubleRatchet(root_key=shared, dh_sk=dh_sk, dh_pk=dh_pk, peer_dh_pk=alice_dh_pub)
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
        send_json_line(conn, out)
        time.sleep(0.01)
except (KeyboardInterrupt, EOFError):
    print("\n[INFO] Exiting")
finally:
    conn.close()
    srv.close()
    sys.exit(0)
