from confidentiality.asymetric import (
    PublicKey,
    public_key_from_bytes,
)
from log import log

CERTIFICATE_LENGTH_BYTES = 8


def split_certificate(certificate: bytes) -> tuple[str, PublicKey]:
    # TODO: Properly split certificate into username and public key.
    #   For now, just assuming first byte is username length

    user_length = int.from_bytes(certificate[:1])
    certificate = certificate[1:]
    log(
        f"Splitting {user_length} from certificate: {certificate[:user_length + 10]}..."
    )
    user = certificate[:user_length].decode()
    log(f"Splitting certificate. User length: {user_length}. User: {user}")

    public_key = public_key_from_bytes(certificate[user_length:])
    return user, public_key
