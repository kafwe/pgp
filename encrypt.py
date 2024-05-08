from typing import Tuple
from cryptography.hazmat import primitives
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


def gen_shared_key() -> bytes:
    key = Fernet.generate_key()
    return key


def encrypt_shared_key(shared_key: bytes, peer_public_key: rsa.RSAPublicKey) -> bytes:
    return peer_public_key.encrypt(shared_key, padding.PKCS1v15())


def decrypt_shared_key(private_key: rsa.RSAPrivateKey, encrypted_shared_key) -> bytes:
    return private_key.decrypt(
        encrypted_shared_key,
        padding.PKCS1v15(),
    )


def gen_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return (private_key, public_key)


def encrypt_message(shared_key: bytes, message: str) -> bytes:
    f = Fernet(shared_key)
    encrypted = f.decrypt(message.encode())
    return encrypted
