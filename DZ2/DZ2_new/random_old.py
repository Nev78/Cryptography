import random

filename = "rnd-random.bin"
size_in_bytes = 10**9  

rng = random.Random()
with open(filename, "wb") as f:
    for _ in range(size_in_bytes):
        f.write(bytes([rng.randint(0, 255)]))
