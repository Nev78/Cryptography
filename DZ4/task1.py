import requests, re, sys

BASE = "https://aes.cryptohack.org/lazy_cbc"

def encrypt_block_zero():
    plaintext_hex = "00" * 16
    url = f"{BASE}/encrypt/{plaintext_hex}/"
    r = requests.get(url)
    r.raise_for_status()
    j = r.json()
    return j.get("ciphertext")

def send_receive(ciphertext_hex):
    url = f"{BASE}/receive/{ciphertext_hex}/"
    r = requests.get(url)
    r.raise_for_status()
    return r.json()

def get_flag(key_hex):
    url = f"{BASE}/get_flag/{key_hex}/"
    r = requests.get(url)
    r.raise_for_status()
    return r.json()

def main():
    try:
        ct = encrypt_block_zero()
        if not ct:
            sys.exit(1)
        c1_hex = ct[:32]
        crafted = c1_hex + ("00" * 16) + c1_hex
        resp = send_receive(crafted)
        err = resp.get("error", "")
        m = re.search(r'([0-9a-fA-F]{96,})', err)
        if not m:
            sys.exit(1)
        decrypted_hex = m.group(1)
        key_hex = decrypted_hex[-32:]
        res_flag = get_flag(key_hex)
        flag_hex = res_flag.get("plaintext")
        if not flag_hex:
            sys.exit(1)
        try:
            flag = bytes.fromhex(flag_hex).decode()
        except Exception:
            flag = flag_hex
        print(flag, end="")
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    main()
