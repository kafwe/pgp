from confidentiality.asymetric import PublicKey, PrivateKey
from confidentiality.symetric import SecretKey

# Number of bytes dedicated to stating the secret's length
SECRET_lENGTH_BYTES = 2


# `data` represents the concatenated encrypted message and secret key
def pgp_decrypt(data: bytes, private_key: PrivateKey) -> bytes:
    e_secret, e_message = _split(data)
    secret = SecretKey(private_key.decrypt(e_secret))
    return secret.decrypt(e_message)


# Returns bytes representing the concatted secret length, encrypted secret, and encrypted message
def pgp_encrypt(message: bytes, peer_public_key: PublicKey) -> bytes:
    secret = SecretKey()
    e_secret = peer_public_key.encrypt(secret.kiv)
    e_message = secret.encrypt(message)
    secret_len = len(e_secret).to_bytes(SECRET_lENGTH_BYTES)
    return secret_len + e_secret + e_message


def _split(data: bytes) -> tuple[bytes, bytes]:
    secret_len = int.from_bytes(data[:SECRET_lENGTH_BYTES])
    data = data[SECRET_lENGTH_BYTES:]
    e_secret = data[:secret_len]
    e_message = data[secret_len:]
    return e_secret, e_message
