import os
from typing import Union
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)

KEY_LENGTH = 32
IV_LENGTH = 32


# Represents the combination of a key and initialisation vector
#   Both are necessary for AES
# IV = Initialisation Vector
class _KeyIV:
    key: bytes
    iv: bytes

    def __init__(self, concatted: Union[bytes, None] = None):
        if concatted is None:
            self.key = os.urandom(KEY_LENGTH)
            self.iv = os.urandom(IV_LENGTH)
        else:
            self.key = concatted[:KEY_LENGTH]
            self.iv = concatted[KEY_LENGTH:]

    def get_concatted(self):
        return self.key + self.iv


class SecretKey:
    encryptor: CipherContext
    decryptor: CipherContext
    CHUNK_SIZE = 1024 * 1024
    kiv: _KeyIV

    def __init__(self, secret_bytes: Union[bytes, None] = None) -> None:
        kiv = _KeyIV(secret_bytes)
        cipher = Cipher(algorithms.AES(kiv.key), modes.CBC(kiv.iv))
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
