import secrets

filename = "rnd-secrets.bin"
size_in_bytes = 10**9

with open(filename, "wb") as f:
    for _ in range(size_in_bytes):
        f.write(bytes([secrets.randbits(8)]))
