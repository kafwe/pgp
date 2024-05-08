import enum
import os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from Encryption.Symetric import Secret


def __gen_half_key() -> bytes:
    return os.urandom(32)


def __encrypt_half_key(key: bytes, peer_public_key: rsa.RSAPublicKey) -> bytes:
    encrypted = peer_public_key.encrypt(key, padding.PKCS1v15())
    return encrypted


def __decrypt_shared_key_half(private_key: rsa.RSAPrivateKey, encrypted_half) -> bytes:
    return private_key.decrypt(
        encrypted_half,
        padding.PKCS1v15(),
    )


# channel is an established connection that messages
# can be received and sent through
def start_diffie_helmen(
    private_key: rsa.RSAPrivateKey, peer_public_key: rsa.RSAPublicKey, channel
) -> Secret:
    bob = __gen_half_key()
    bob_encrypted = __encrypt_half_key(bob, peer_public_key)
    channel.send(bob_encrypted)

    alice_encrypted = channel.receive()
    alice = __decrypt_shared_key_half(private_key, alice_encrypted)

    return Secret(bob, alice)


def receive_diffie_helmen(
    private_key: rsa.RSAPrivateKey, peer_public_key: rsa.RSAPublicKey, channel
) -> Secret:

    bob_encrypted = channel.receive()
    bob = __decrypt_shared_key_half(private_key, bob_encrypted)

    alice = __gen_half_key()
    alice_encrypted = __encrypt_half_key(bob, peer_public_key)
    channel.send(alice_encrypted)

    return Secret(bob, alice)
