from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
import os

# ---------------------- Утиліти ----------------------
# Допоміжні функції, які використовуються обома сторонами протоколу.
# Утиліти виконують: генерацію RSA-пари, підпис/перевірку підпису та похідний симетричний ключ.

# Генеруємо RSA приватний і публічний ключі для підписів.
# Логіка: повертаємо пару (private_key, public_key) — приватний для підпису, публічний для роздачі.
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


# Підписуємо повідомлення за допомогою RSA-PSS + SHA256.
# Логіка: будь-яка сторона викликає цю функцію, щоб підписати свої DH public bytes перед відправкою.
def rsa_sign(private_key, message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature


# Перевіряємо підпис; повертаємо True якщо підпис валідний, інакше False.
# Логіка: приймаюча сторона використовує це, щоб підтвердити, що DH value підписано відповідним RSA приватним ключем.
def rsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# Одержуємо симетричний ключ через HKDF-SHA256 (32 байти).
# Логіка: після DH-exchange обидві сторони викликають цю функцію, щоб отримати ідентичний симетричний ключ.
def derive_symmetric_key(shared_key: bytes, info: bytes = b"auth-dh") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_key)


# ---------------------- Сторона (Party) ----------------------
# Тут реалізовуємо клас, який інкапсулює логіку однієї сторони (наприклад, Alice або Bob).
# В конструкторі генеруються локальні ключі; є метод для створення handshake-повідомлення
# та метод для обробки вхідного пакета (верифікація, перевірки, обчислення shared_secret).

class Party:

    def __init__(self, name: str, dh_parameters: dh.DHParameters):
        self.name = name

        # Генеруємо RSA ключі для сторони.
        # Логіка: приватний — для підпису, публічний — для роздачі іншим учасникам.
        self.rsa_private, self.rsa_public = generate_rsa_keypair()

        # Генеруємо ephemeral DH ключі на основі загальних параметрів.
        # Логіка: ці DH ключі будуть використані для обчислення спільного секрету.
        self.dh_parameters = dh_parameters
        self.dh_private = self.dh_parameters.generate_private_key()
        self.dh_public = self.dh_private.public_key()

        # Зберігаємо результати обміну (shared secret і похідний симетричний ключ).
        self.shared_secret = None
        self.symmetric_key = None

    # Повертаємо PEM-байти публічного RSA ключа.
    # Логіка: інша сторона використовує ці байти, щоб верифікувати підпис.
    def get_rsa_public_bytes(self) -> bytes:
        return self.rsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # Серіалізовуємо DH public value у байти фіксованої довжини.
    # Логіка: гарантувати стабільну довжину представлення 'y' для передачі та верифікації.
    def _dh_public_bytes(self) -> bytes:
        pub_numbers = self.dh_public.public_numbers()
        p_bitlen = self.dh_parameters.parameter_numbers().p.bit_length()
        length = (p_bitlen + 7) // 8
        y = pub_numbers.y
        return y.to_bytes(length, byteorder="big")

    # Створюємо handshake-пакет: dh_pub bytes + підпис + PEM публічного RSA.
    # Логіка: серіалізувати DH public, підписати його, додати свій RSA public для верифікації одержувачем.
    def create_handshake_message(self) -> dict:
        dh_pub_bytes = self._dh_public_bytes()
        signature = rsa_sign(self.rsa_private, dh_pub_bytes)
        return {
            "dh_pub": dh_pub_bytes,
            "sig": signature,
            "rsa_pub": self.get_rsa_public_bytes(),
        }

    # Обробляємо вхідний handshake-пакет.
    # Логіка:
    # 1) Завантажуємо RSA public peer-а з PEM,
    # 2) Перевіряємо підпис на peer_dh_pub_bytes (якщо невірно — відкидаємо),
    # 3) Перевіряємо довжину peer_dh_pub_bytes (формат/цілісність),
    # 4) Відновлюємо DHPublicKey з байтів,
    # 5) Виконуємо DH exchange: my_private.exchange(peer_pub),
    # 6) Генеруємо похідний симетричний ключ через HKDF.
    def receive_and_process(self, packet: dict) -> bytes:
        peer_dh_pub_bytes = packet.get("dh_pub")
        peer_signature = packet.get("sig")
        peer_rsa_pub_bytes = packet.get("rsa_pub")

        # Завантажуємо публічний RSA ключ peer-а для верифікації.
        peer_rsa_public = serialization.load_pem_public_key(peer_rsa_pub_bytes)

        # Перевіряємо підпис; якщо підпис невірний — підозра MITM, то відкидаємо пакет.
        if not rsa_verify(peer_rsa_public, peer_dh_pub_bytes, peer_signature):
            raise ValueError(f"{self.name}: Підпис peer-а невалідний! Можлива спроба MITM.")

        # Перевіряємо довжину публічного DH значення — переконуємось у форматі/цілісності.
        p = self.dh_parameters.parameter_numbers().p
        p_bitlen = p.bit_length()
        length = (p_bitlen + 7) // 8
        if len(peer_dh_pub_bytes) != length:
            raise ValueError(f"{self.name}: Неправильна довжина публічного DH значення (очікувалось {length}).")

        # Відновлюємо числове значення y і створюємо DHPublicKey об'єкт.
        y = int.from_bytes(peer_dh_pub_bytes, byteorder="big")
        param_nums = self.dh_parameters.parameter_numbers()
        peer_pub_numbers = dh.DHPublicNumbers(y, param_nums)
        peer_pub = peer_pub_numbers.public_key()

        # Виконуємо DH exchange і зберігаємо спільний секрет.
        shared = self.dh_private.exchange(peer_pub)
        self.shared_secret = shared

        # Логуємо (для демонстрації), що підпис пройшов і спільний секрет обчислено.
        print(f"{self.name}: Успішно перевірено підпис. Обчислено shared_secret (len={len(shared)}).")

        # Отримуємо похідний симетричний ключ через HKDF і повертаємо його.
        self.symmetric_key = derive_symmetric_key(shared, info=b"auth-dh-v1")
        print(f"{self.name}: Виведений симетричний ключ: {self.symmetric_key.hex()}\n")
        return self.symmetric_key


# ---------------------- Симульована мережа ----------------------
# Канал передачі: простий ретранслятор пакета.
# Логіка: повертаємо отриманий пакет; тестувальник може змінити цю функцію, щоб симулювати MITM.
def simulated_send(packet: dict) -> dict:
    return packet


# -------------------------- Сценарії  --------------------------
# Реалізовуємо два сценарії: нормальна симуляція протоколу та демонстрація MITM.

# 1) Виконуємо повну симуляцію автентифікованого DH: обидві сторони підписують свої DH-public.
def simulate_protocol():
    print("--- Симуляція автентифікованого DH (RSA-PSS підписи) ---\n")

    # Генеруємо спільні DH параметри (p,g) для обох сторін.
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Створюємо Alice і Bob; кожен з них генерує локальні RSA та DH ключі в конструкторі.
    alice = Party("Alice", dh_parameters)
    bob = Party("Bob", dh_parameters)

    # Логіка Alice: підготувати handshake (її DH_pub + підпис + її RSA_pub) і відправити.
    alice_packet = alice.create_handshake_message()

    # ALICE -> канал -> BOB 
    sent_to_bob = simulated_send(alice_packet)

    # Логіка Bob: отримати пакет, верифікувати підпис, побудувати peer_pub, обчислити shared_secret і ключ.
    bob_key = bob.receive_and_process(sent_to_bob)

    # Логіка Bob: сформувати свій handshake і відправити назад Alice.
    bob_packet = bob.create_handshake_message()
    sent_to_alice = simulated_send(bob_packet)

    # Логіка Alice: отримати пакет від Bob і виконати ті ж перевірки та DH-exchange.
    alice_key = alice.receive_and_process(sent_to_alice)

    # Перевіряємо, що обидва симетричні ключі співпадають.
    assert alice_key == bob_key, "Ключі не співпали!"
    print(" Симуляція успішна: Alice і Bob отримали однаковий симетричний ключ.")


# 2) Демонструємо MITM: Mallory намагається підмінити DH-public без приватного RSA ключа.
def simulate_mitm_attack():
    print("--- Демонстрація MITM: спроба підміни DH публічного ключа без RSA приватного ключа ---\n")

    # Генеруємо спільні DH параметри.
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Створюємо легітимні сторони Alice і Bob.
    alice = Party("Alice", dh_parameters)
    bob = Party("Bob", dh_parameters)

    # Логіка Mallory: генерує власний DH ключ, але не має приватного RSA ключа Alice/Bob,
    # тому не може створити валідний підпис для підміни.
    mallory_priv = dh_parameters.generate_private_key()
    mallory_pub = mallory_priv.public_key()
    p_bitlen = dh_parameters.parameter_numbers().p.bit_length()
    length = (p_bitlen + 7) // 8
    mallory_y = mallory_pub.public_numbers().y
    mallory_pub_bytes = mallory_y.to_bytes(length, byteorder="big")

    # Логіка Alice: формує нормальний пакет і відправляє.
    alice_packet = alice.create_handshake_message()

    # Логіка Mallory (атака): підміняє dh_pub, але не може надати валідний підпис.
    fake_packet = {
        "dh_pub": mallory_pub_bytes,
        "sig": b"\x00" * 256,  # навмисно некоректний підпис для демонстрації
        "rsa_pub": alice.get_rsa_public_bytes(),
    }

    # Логіка Bob: спробує обробити підмінений пакет; перевірка підпису має провалитися.
    try:
        bob.receive_and_process(fake_packet)
    except ValueError as e:
        print(f"Боб: Повідомлення відхилено — {e}")

    # Логіка у зворотному напрямку: Bob формує пакет, Mallory підміняє DH, Alice також відкине.
    bob_packet = bob.create_handshake_message()
    fake_packet2 = {
        "dh_pub": mallory_pub_bytes,
        "sig": b"\x00" * 256,
        "rsa_pub": bob.get_rsa_public_bytes(),
    }
    try:
        alice.receive_and_process(fake_packet2)
    except ValueError as e:
        print(f"Аліса: Повідомлення відхилено — {e}")

    # Підсумовуємо висновок по демонстрації.
    print("\n Висновок: без доступу до приватного RSA ключа підміна DH-публічного ключа не пройде верифікацію.")


if __name__ == "__main__":
    # Запускаємо демонстраційні сценарії: спочатку нормальну симуляцію, потім MITM.
    simulate_protocol()
    print("\n")
    simulate_mitm_attack()
    print("\n--- Кінець симуляції ---\n")
