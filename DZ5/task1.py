from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16
)

passwords = [
    "qwertyuiop",
    "sofPed-westag-jejzo1",
    "f3Fg#Puu$EA1mfMx2",
    "TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh"
]

with open("hashed_passwords.txt", "w") as f:
    for pwd in passwords:
        hashed = ph.hash(pwd)
        f.write(hashed + "\n")
        print(hashed)
