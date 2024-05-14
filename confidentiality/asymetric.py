from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization as srlz
from cryptography.exceptions import InvalidSignature


class PublicKey:
    key: rsa.RSAPublicKey

    def __init__(self, key: rsa.RSAPublicKey) -> None:
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        return self.key.encrypt(data, padding.PKCS1v15())

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    def save(self, fileName: str = "public_keys"):
        data = self.key.public_bytes(
            srlz.Encoding.PEM,
            srlz.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(f"keys/{fileName}", "wb") as file:
            file.write(data)


class PrivateKey:
    key: rsa.RSAPrivateKey

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self.key = key

    def decrypt(self, data: bytes) -> bytes:
        return self.key.decrypt(
            data,
            padding.PKCS1v15(),
        )

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    def get_public_key(self) -> PublicKey:
        return PublicKey(self.key.public_key())

    def save(
        self,
        fileName: str = "private_key",
        password: str | None = None,
    ) -> None:
        if password is not None:
            data = self.key.private_bytes(
                srlz.Encoding.PEM,
                srlz.PrivateFormat.PKCS8,
                srlz.BestAvailableEncryption(password.encode()),
            )
        else:
            data = self.key.private_bytes(
                srlz.Encoding.PEM,
                srlz.PrivateFormat.TraditionalOpenSSL,
                srlz.NoEncryption(),
            )

        with open(f"keys/{fileName}", "wb") as file:
            file.write(data)


def generate_key_pair() -> tuple[PrivateKey, PublicKey]:
    private_key = rsa.generate_private_key(65537, 2048)
    public_key = private_key.public_key()
    return PrivateKey(private_key), PublicKey(public_key)


def load_private_key(
    fileName: str = "private_key", password: str | None = None
) -> PrivateKey:
    with open(f"keys/{fileName}", "rb") as key_file:
        return private_key_from_bytes(key_file.read(), password)


def load_public_key(fileName: str = "public_key") -> PublicKey:
    with open(f"keys/{fileName}", "rb") as key_file:
        return public_key_from_bytes(key_file.read())


def load_public_key_bytes(fileName: str = "public_key") -> bytes:
    with open(f"keys/{fileName}", "rb") as key_file:
        return key_file.read()


def public_key_from_bytes(data: bytes) -> PublicKey:
    public_key = srlz.load_pem_public_key(data, None)
    assert isinstance(public_key, rsa.RSAPublicKey)
    return PublicKey(public_key)


def private_key_from_bytes(data: bytes, password: str | None = None) -> PrivateKey:
    if password is not None:
        pw = password.encode()
    else:
        pw = None
    private_key = srlz.load_pem_private_key(data, pw)
    assert isinstance(private_key, rsa.RSAPrivateKey)
    return PrivateKey(private_key)
