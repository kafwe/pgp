import os

from Confidentiality.Symetric import Secret
from Confidentiality.Asymetric import PublicKey
from Confidentiality.Asymetric import PrivateKey


def __gen_half_key() -> bytes:
    return os.urandom(32)


def start_diffie_helmen(
    private_key: PrivateKey, peer_public_key: PublicKey, channel
) -> Secret:

    user_half = __gen_half_key()
    user_half_encrypted = peer_public_key.encrypt(user_half)
    channel.send(user_half_encrypted)

    peer_half_encrypted = channel.receive()
    peer_half = private_key.decrypt(peer_half_encrypted)

    return Secret(user_half, peer_half)


def receive_diffie_helmen(
    private_key: PrivateKey, peer_public_key: PublicKey, channel
) -> Secret:

    peer_half_encrypted = channel.receive()
    peer_half = private_key.decrypt(peer_half_encrypted)

    user_half = __gen_half_key()
    user_half_encrypted = peer_public_key.encrypt(user_half)
    channel.send(user_half_encrypted)

    return Secret(peer_half, user_half)
