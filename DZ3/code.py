#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, time
from binascii import hexlify
import requests
import string

API_BASE = "http://aes.cryptohack.org/ecb_oracle/encrypt/"
CHARSET = string.ascii_lowercase + string.digits + '_{}'


def encrypt(pt: str) -> str:
    safe_pt = pt if len(pt) > 0 else "A"
    hex_text = hexlify(safe_pt.encode()).decode()
    url = API_BASE + hex_text
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    j = r.json()
    if "ciphertext" not in j:
        raise RuntimeError("No ciphertext in response")
    return j["ciphertext"]

def detect_block_size():
    prev = len(encrypt("A"))
    for i in range(2, 129):
        cur = len(encrypt("A" * i))
        if cur > prev:
            return (cur - prev) // 2
    raise RuntimeError("block size detect failed")

def is_ecb(block_size):
    data = "B" * (block_size * 8)
    ct = encrypt(data)
    blocks = [ct[i:i+block_size*2] for i in range(0, len(ct), block_size*2)]
    return len(blocks) != len(set(blocks))

def recover_flag(block_size, max_len=300, delay=0.01):
    recovered = ""
    print("[*] Recovery:")
    for _ in range(max_len):
        pad_len = (block_size - (len(recovered) % block_size) - 1)
        pad = "A" * block_size if pad_len == 0 else "A" * pad_len

        target_ct = encrypt(pad)
        block_index = (len(pad) + len(recovered)) // block_size
        start = block_index * block_size * 2
        end = start + block_size * 2
        if end > len(target_ct):
            target_ct = encrypt(pad + "A" * block_size)
        target_block = target_ct[start:end]

        found = False
        for ch in CHARSET:
            attempt = pad + recovered + ch
            attempt_ct = encrypt(attempt)
            attempt_block = attempt_ct[start:end]
            if attempt_block == target_block:
                recovered += ch
                sys.stdout.write(ch)
                sys.stdout.flush()
                found = True
                break
            time.sleep(delay)

        if not found:
            print("\n[!] No suitable symbol found.")
            print("    - flag's over;")
            print("    - there are characters in the flag that are not in CHARSET;")
            print("    - a different approach is needed for the end of the line.")
            break

        if recovered.endswith("}"):
            print("\n[+] Found closing '}' — probably full flag.")
            break

    return recovered

def main():
    print("[*] Detecting AES block size...")
    bs = detect_block_size()
    print(f"[+] Block size = {bs}")
    if not is_ecb(bs):
        print("[!] It doesn't appear to be ECB mode")
        return
    flag = recover_flag(bs)
    print("\n[RESULT] ", flag)

if __name__ == "__main__":
    main()
