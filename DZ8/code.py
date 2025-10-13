from cryptography.hazmat.primitives.asymmetric import ec, x25519, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from binascii import hexlify, unhexlify

alice_pub_sign_key_raw = b"""
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES/35y89DRx2XEh6pJvCckadQ9Awuys84
HORPVVaDksVxWfSkngYrz/c+HwVS9tV5ivnVwCHxyJ8gTQob/0LDDg==
-----END PUBLIC KEY-----
"""
alice_pub_sign_key = serialization.load_pem_public_key(alice_pub_sign_key_raw)

alice_x_pub_key = unhexlify(b'92ce3bc6d941238da92639c72a7d3bb483d3c18fdca9f42164459a3751638433')
signature = unhexlify(
    b'3045022034b7944bf92bfaa2791b5fe929d915add4ee59dbd9e776c1520568fbf2503048022100f09c9113f38fadb33b05332eab9a4982f7dda35fb1f503bb46da806c8e8dbaa2'
)

bob_sign_private_key = ec.generate_private_key(ec.SECP256K1())
bob_sign_public_key = bob_sign_private_key.public_key()

bob_ecdh_private_key = x25519.X25519PrivateKey.generate()
bob_ecdh_public_key = bob_ecdh_private_key.public_key()

try:
    alice_pub_sign_key.verify(
        signature,
        alice_x_pub_key,
        ec.ECDSA(hashes.SHA256())
    )
    print("Підпис Alice перевірено успішно ")
except InvalidSignature:
    print("Підпис Alice недійсний ")

bob_ecdh_pub_bytes = bob_ecdh_public_key.public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw
)

bob_signature = bob_sign_private_key.sign(
    bob_ecdh_pub_bytes,
    ec.ECDSA(hashes.SHA256())
)

bob_sign_pub_pem = bob_sign_public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

print("\n=== Результати для відправки Alice ===")
print(" Відкритий ключ підпису Боба (PEM):\n", bob_sign_pub_pem.decode())
print(" Відкритий ключ ECDH Боба (hex):", hexlify(bob_ecdh_pub_bytes).decode())
print(" Підпис відкритого ключа ECDH Боба (hex):", hexlify(bob_signature).decode())

with open("bob_keys.txt", "w") as f:
    f.write("=== Відкритий ключ підпису Боба (PEM) ===\n")
    f.write(bob_sign_pub_pem.decode())
    f.write("\n=== Відкритий ключ ECDH Боба (hex) ===\n")
    f.write(hexlify(bob_ecdh_pub_bytes).decode())
    f.write("\n=== Підпис відкритого ключа ECDH Боба (hex) ===\n")
    f.write(hexlify(bob_signature).decode())
