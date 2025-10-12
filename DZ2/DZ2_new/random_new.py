
import random
import argparse
from pathlib import Path

def gen_random_file(filename, target_bytes=1_000_000_000, chunk_size=1_000_000):
    
    rnd = random.Random()  
    p = Path(filename)
    with p.open("wb") as f:
        written = 0
        while written < target_bytes:
            this_chunk = min(chunk_size, target_bytes - written)
            ba = bytearray(this_chunk)
            for i in range(this_chunk):
                ba[i] = rnd.randint(0, 255)
            f.write(ba)
            written += this_chunk
            if written % (100 * chunk_size) == 0:
                print(f"Written {written} bytes")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="rnd-random.bin")
    parser.add_argument("--size", type=int, default=1_000_000_000)
    args = parser.parse_args()
    gen_random_file(args.out, args.size)
