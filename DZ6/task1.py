from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

with open("task_pub.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

with open("task_message.txt", "r") as msg_file:
    message = bytes.fromhex(msg_file.read().strip())

with open("task_signature.txt", "r") as sig_file:
    signature = bytes.fromhex(sig_file.read().strip())

try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature verified successfully")
except Exception as e:
    print("Signature not verified")
