

import os
import sys
from math import ceil

SEQ_FILE = "sequence.txt"
ENC_FILE = "data.bmp.enc"
OUT_BMP = "data.bmp"
OUT_KEY = "key_hex.txt"
MAX_ADVANCE = 20000
STATUS_EVERY = 500

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    def aes_ecb_decrypt(key_bytes, data):
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
except Exception:
    try:
        from Crypto.Cipher import AES
        def aes_ecb_decrypt(key_bytes, data):
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            return cipher.decrypt(data)
    except Exception:
        
        sys.exit(1)


w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
MASK_32 = 0xFFFFFFFF

def un_bitshift_right_xor(y, shift):
    res = 0
    for i in range(0, w, shift):
        part_mask = ((1 << shift) - 1) << (w - shift - i)
        part = y & part_mask
        res |= part
        prev = res >> shift
        y ^= prev
    return res & MASK_32

def un_bitshift_left_xor_and(y, shift, mask):
    res = 0
    for i in range(0, w, shift):
        part_mask = ((1 << shift) - 1) << i
        part = y & part_mask
        res |= part
        prev = (res << shift) & mask
        y ^= prev
    return res & MASK_32

def untemper(y):
    y = int(y) & MASK_32
    y = un_bitshift_right_xor(y, l)
    y = un_bitshift_left_xor_and(y, t, c)
    y = un_bitshift_left_xor_and(y, s, b)
    y = un_bitshift_right_xor(y, u)
    return y & MASK_32

class MT19937:
    def __init__(self):
        self.mt = [0] * n
        self.index = n

    def seed_from_state(self, state_array):
        if len(state_array) != n:
            raise ValueError("state_array must be length 624")
        self.mt = list(state_array)
        self.index = n

    def twist(self):
        upper_mask = (~((1 << r) - 1)) & MASK_32
        lower_mask = ((1 << r) - 1) & MASK_32
        for i in range(n):
            x = (self.mt[i] & upper_mask) + (self.mt[(i+1) % n] & lower_mask)
            xA = x >> 1
            if x & 1:
                xA ^= a
            self.mt[i] = self.mt[(i + m) % n] ^ xA
        self.index = 0

    def extract_number(self):
        if self.index >= n:
            self.twist()
        y = self.mt[self.index]
        y ^= (y >> u) & d
        y ^= (y << s) & b
        y ^= (y << t) & c
        y ^= (y >> l)
        self.index += 1
        return y & MASK_32

def read_sequence_file(fname):
    if not os.path.exists(fname):
        print(f"Не знайдено {fname}")
        sys.exit(1)
    data = open(fname, "r", encoding="utf-8").read().strip()
    if not data:
        sys.exit(1)

    seq = None
    try:
        maybe = eval(data, {"__builtins__": None}, {})
        if isinstance(maybe, (list, tuple)):
            seq = list(maybe)
    except Exception:
        seq = None

    if seq is None:
        parts = []
        for line in data.splitlines():
            for part in line.strip().split():
                if part:
                    parts.append(part)
        seq = []
        for p in parts:
            try:
                seq.append(int(p, 0))  
            except Exception:
                try:
                    seq.append(int(p, 16))
                except Exception:
                    print("Не можу розпарсити елемент із sequence.txt:", p)
                    sys.exit(1)
    return seq

def to_32bit_outputs(raw_values):
    outputs32 = []
    for v in raw_values:
        v = int(v)
        bitlen = v.bit_length()
        blocks = max(1, ceil(bitlen / 32))
        for i in range(blocks):
            shift = (blocks - 1 - i) * 32
            chunk = (v >> shift) & MASK_32
            outputs32.append(chunk)
    return outputs32

def main():
    #print("  Читаю послідовність...")
    raw_seq = read_sequence_file(SEQ_FILE)
    print(f"  Прочитано {len(raw_seq)} елемент(ів) з {SEQ_FILE}")

    outputs32 = to_32bit_outputs(raw_seq)
    print(f"  Отримано {len(outputs32)} 32-бітних виходів після розбиття")

    if len(outputs32) < 624:
        print(" Для повного відновлення MT19937 потрібно щонайменше 624 32-бітних виходів.")
        print(" Отримано:", len(outputs32))
        sys.exit(1)

    state_outputs = outputs32[-624:]
    print("  Використовую останні 624 виходи для відновлення стану MT19937.")

    use_external = False
    try:
        from mt19937_reverse import MT19937Reverse
        rev = MT19937Reverse()
        mt_gen_base = rev.reverse(state_outputs)  
        use_external = True
        print("  Знайдено mt19937_reverse, використовую його для відновлення.")
    except Exception:
        use_external = False
        print("  Не знайдено mt19937_reverse, буду використовувати локальний унтемпер-фолбек.")
        untempered = [untemper(y) for y in state_outputs]
        mt_gen_base = MT19937()
        mt_gen_base.seed_from_state(untempered)

    if not os.path.exists(ENC_FILE):
        print(f" Не знайдено {ENC_FILE}")
        sys.exit(1)
    encdata = open(ENC_FILE, "rb").read()

    print("  Починаю перебір можливих зсувів (advance)...")
    for advance in range(0, MAX_ADVANCE + 1):
        if advance % STATUS_EVERY == 0:
            print(f"    Перевірка advance = {advance} / {MAX_ADVANCE} ...")

        if use_external:
            import copy
            m = copy.deepcopy(mt_gen_base)  
            for _ in range(advance):
                _ = m.getrandbits(32)
            parts = [m.getrandbits(32) for _ in range(4)]
        else:
            m = MT19937()
            m.seed_from_state(list(untempered))
            for _ in range(advance):
                _ = m.extract_number()
            parts = [m.extract_number() for _ in range(4)]

        key_int = (parts[0] << 96) | (parts[1] << 64) | (parts[2] << 32) | parts[3]
        key_bytes_le = key_int.to_bytes(16, byteorder="little")

        try:
            plain = aes_ecb_decrypt(key_bytes_le, encdata)
        except Exception:
            continue

        if len(plain) >= 2 and plain[0:2] == b'BM':
            print("  Ключ знайдено! advance =", advance)
            hex_repr = key_bytes_le.hex()
            with open(OUT_KEY, "w") as fk:
                fk.write(hex_repr + "\n")
            with open(OUT_BMP, "wb") as fb:
                fb.write(plain)
            print(f"  Збережено ключ у {OUT_KEY} та розшифроване зображення у {OUT_BMP}")
            print(f"  Ключ (hex, little-endian bytes): {hex_repr}")
            print(f"  Ключ (big-endian hex int): {key_int:032x}")
            return

    
    return

if __name__ == "__main__":
    main()
