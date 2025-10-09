import requests
from binascii import unhexlify, hexlify

BASE_URL = "https://aes.cryptohack.org"  

GET_COOKIE_PATH = "/flipping_cookie/get_cookie/"
CHECK_ADMIN_PATH = "/flipping_cookie/check_admin/{cipher}/{iv}/"

def get_cookie():
    url = BASE_URL.rstrip("/") + GET_COOKIE_PATH
    r = requests.get(url)
    r.raise_for_status()
    return r.json()["cookie"].strip()

def call_check_admin(cipher_hex, iv_hex):
    url = BASE_URL.rstrip("/") + CHECK_ADMIN_PATH.format(cipher=cipher_hex, iv=iv_hex)
    r = requests.get(url)
    try:
        return r.json()
    except ValueError:
        return {"error": r.text.strip()}

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    try:
        full = get_cookie()
        iv_hex = full[:32]
        enc_hex = full[32:]
        iv = unhexlify(iv_hex)
        enc = unhexlify(enc_hex)

        orig_block0 = b"admin=False;expi"  
        desired_block0 = b";admin=True;expi"  

        delta = xor_bytes(orig_block0, desired_block0)
        new_iv = xor_bytes(iv, delta)

        resp = call_check_admin(hexlify(enc).decode(), hexlify(new_iv).decode())

        if isinstance(resp, dict) and "flag" in resp:
            print(resp["flag"])
        elif isinstance(resp, dict) and "error" in resp:
            print(resp["error"])
        else:
            print("Unexpected response")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
