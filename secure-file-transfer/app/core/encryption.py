from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_SIZE = 32  # AES-256
BLOCK_SIZE = 16


def generate_key() -> bytes:
    return get_random_bytes(KEY_SIZE)


def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes) -> bytes:
    return data[: -data[-1]]


def encrypt_file(file_path: str, key: bytes, output_path: str):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(file_path, "rb") as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext))
    with open(output_path, "wb") as f:
        f.write(iv + ciphertext)


def decrypt_file(enc_path: str, key: bytes, output_path: str):
    with open(enc_path, "rb") as f:
        iv = f.read(BLOCK_SIZE)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    with open(output_path, "wb") as f:
        f.write(plaintext)
