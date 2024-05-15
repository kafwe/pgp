import os

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives import padding
from log import log

KEY_LENGTH = 32
IV_LENGTH = 16


class SecretKey:
    encryptor: CipherContext
    decryptor: CipherContext
    CHUNK_SIZE = 1024 * 1024
    kiv: bytes

    def __init__(self, secret_bytes: bytes | None = None) -> None:
        key, iv = self._key_iv(secret_bytes)
        log(f"Key = {key} | iv = {iv}")
        self.kiv = key + iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, message: bytes) -> bytes:
        padded = _pad(message)
        return self._chunk(padded, self.encryptor)

    def decrypt(self, encrypted: bytes) -> bytes:
        message = self._chunk(encrypted, self.decryptor)
        unpadded = _unpad(message)
        return unpadded

    def _chunk(self, data: bytes, cipher: CipherContext) -> bytes:
        res: bytes = b""
        while True:
            chunk = data[: self.CHUNK_SIZE]
            data = data[self.CHUNK_SIZE :]
            if len(chunk) == 0:
                res += cipher.finalize()
                break
            res += cipher.update(chunk)
        return res

    # Represents the combination of a key and initialisation vector
    #   Both are necessary for AES
    # IV = Initialisation Vector
    def _key_iv(self, concatted: bytes | None = None) -> tuple[bytes, bytes]:
        if concatted is None:
            key = os.urandom(KEY_LENGTH)
            iv = os.urandom(IV_LENGTH)
        else:
            key = concatted[:KEY_LENGTH]
            iv = concatted[KEY_LENGTH:]
        return key, iv


def _pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    return padded


def _unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(data) + unpadder.finalize()
    return unpadded
