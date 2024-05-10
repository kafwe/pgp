from typing import Tuple
from confidentiality.asymetric import PublicKey, PrivateKey
from confidentiality.symetric import SecretKey

# Number of bytes dedicated to stating the secret's length
SECRET_lENGTH_BYTES = 2


# `data` represents the concatenated encrypted message and secret key
def pgp_decrypt(data: bytes, private_key: PrivateKey) -> bytes:
    encrypted_secret, encrypted_message = _split(data)
    secret = SecretKey(private_key.decrypt(encrypted_secret))
    return secret.decrypt(encrypted_message)


def pgp_encrypt(message: bytes, peer_public_key: PublicKey) -> bytes:
    secret = SecretKey()
    encrypted_secret = peer_public_key.encrypt(secret.kiv)
    encrypted_message = secret.encrypt(message)
    secret_length = len(encrypted_secret).to_bytes(SECRET_lENGTH_BYTES, byteorder="big")
    return secret_length + encrypted_secret + encrypted_message


def _split(data: bytes) -> Tuple[bytes, bytes]:
    secret_length = int.from_bytes(data[:SECRET_lENGTH_BYTES], byteorder="big")
    data = data[SECRET_lENGTH_BYTES:]
    encrypted_secret = data[:secret_length]
    encrypted_message = data[secret_length:]
    return encrypted_secret, encrypted_message
