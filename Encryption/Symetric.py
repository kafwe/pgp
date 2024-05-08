import os
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)


class Secret:
    CHUNK_SIZE = 1024 * 1024
    encryptor: CipherContext
    decryptor: CipherContext

    # Bob is user establishing connection
    # Alice is user receiving connection
    # Halves must already be decrypted
    def __init__(self, bob_half: bytes, alice_half: bytes) -> None:
        key = bob_half + alice_half
        iv = os.urandom(64)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, message: str) -> bytes:
        return self.__chunk(message.encode(), self.encryptor)

    def decrypt(self, encrypted: bytes) -> str:
        return self.__chunk(encrypted, self.decryptor).decode()

    def __chunk(self, data: bytes, cipher: CipherContext) -> bytes:
        res: bytes = b""
        while True:
            chunk = data[: self.CHUNK_SIZE]
            data = data[self.CHUNK_SIZE :]
            if len(chunk) == 0:
                break
            res += cipher.update(chunk)
        return res + cipher.finalize()
