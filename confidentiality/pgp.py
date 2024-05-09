from confidentiality.asymetric import PublicKey, PrivateKey
from confidentiality.symetric import KeyIV, SecretKey


class PGP:
    encrypted_message: bytes
    encrypted_secret: bytes

    def __init__(self, encrypted_message, encrypted_secret):
        self.encrypted_message = encrypted_message
        self.encrypted_secret = encrypted_secret

    def decrypt_message(self, private_key: PrivateKey) -> bytes:
        kiv = KeyIV(private_key.decrypt(self.encrypted_secret))
        secret = SecretKey(kiv)
        return secret.decrypt(self.encrypted_message)


def gen_pgp(message: bytes, peer_public_key: PublicKey) -> PGP:
    secret = SecretKey()
    encrypted_secret = peer_public_key.encrypt(secret.kiv.get_concatted())
    encrypted_message = secret.encrypt(message)
    return PGP(encrypted_message, encrypted_secret)
