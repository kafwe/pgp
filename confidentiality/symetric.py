import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)

KEY_LENGTH = 32
IV_LENGTH = 32


class SecretKey:
    encryptor: CipherContext
    decryptor: CipherContext
    CHUNK_SIZE = 1024 * 1024
    kiv: bytes

    def __init__(self, secret_bytes: bytes | None = None) -> None:
        key, iv = self._key_iv(secret_bytes)
        self.kiv = key + iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, message: bytes) -> bytes:
        return self._chunk(message, self.encryptor)

    def decrypt(self, encrypted: bytes) -> bytes:
        return self._chunk(encrypted, self.decryptor)

    def _chunk(self, data: bytes, cipher: CipherContext) -> bytes:
        res: bytes = b""
        while True:
            chunk = data[: self.CHUNK_SIZE]
            data = data[self.CHUNK_SIZE :]
            if len(chunk) == 0:
                break
            res += cipher.update(chunk)
        return res + cipher.finalize()

    # Represents the combination of a key and initialisation vector
    #   Both are necessary for AES
    # IV = Initialisation Vector
    def _key_iv(self, concatted: bytes | None = None) -> Tuple[bytes, bytes]:
        if concatted is None:
            key = os.urandom(KEY_LENGTH)
            iv = os.urandom(IV_LENGTH)
        else:
            key = concatted[:KEY_LENGTH]
            iv = concatted[KEY_LENGTH:]
        return key, iv
