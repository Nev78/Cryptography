from Crypto.Hash import HMAC, SHA256
from binascii import unhexlify, hexlify

key_hex = "63e353ae93ecbfe00271de53b6f02a46"
key = unhexlify(key_hex)

iv_hex = "75b777fc8f70045c6006b39da1b3d622"
ciphertext_hex = "76c3ada7f1f7563ff30d7290e58fb4476eb12997d02a6488201c075da52ff3890260e2c89f631e7f919af96e4e47980a"

iv = unhexlify(iv_hex)
ciphertext = unhexlify(ciphertext_hex)

data = iv + ciphertext

h = HMAC.new(key, data, SHA256)
mac = h.digest()

mac_hex = hexlify(mac).decode()
print("MAC (hex):", mac_hex)

with open("mac.txt", "w") as f:
    f.write(mac_hex)
