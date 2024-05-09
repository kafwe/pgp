from typing import Tuple

from cryptography.hazmat.primitives import serialization as srlz

from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    generate_key_pair,
    load_private_key,
    load_public_key,
)

from tests.file_names import (
    a_private_f,
    a_public_f,
    b_private_f,
    b_public_f,
    a_pgps_f,
    b_pgps_f,
)


def gen_and_save_keys() -> (
    Tuple[Tuple[PrivateKey, PublicKey], Tuple[PrivateKey, PublicKey]]
):
    a_private, a_public = generate_key_pair()
    b_private, b_public = generate_key_pair()

    a_private.save(a_private_f, "secure_password")
    a_public.save(a_public_f)
    b_private.save(b_private_f, "secure_password")
    b_public.save(b_public_f)
    return (a_private, a_public), (b_private, b_public)


def read_private_keys() -> Tuple[PrivateKey, PrivateKey]:
    alice = load_private_key(a_private_f, "secure_password")
    bob = load_private_key(b_private_f, "secure_password")
    return alice, bob


def read_public_keys() -> Tuple[PublicKey, PublicKey]:
    alice = load_public_key(a_public_f)
    bob = load_public_key(b_public_f)
    return alice, bob


def show_private_key(key: PrivateKey) -> str:
    data = key.key.private_bytes(
        srlz.Encoding.PEM,
        srlz.PrivateFormat.TraditionalOpenSSL,
        srlz.NoEncryption(),
    )
    return data.decode()


def show_public_key(key: PublicKey) -> str:
    data = key.key.public_bytes(
        srlz.Encoding.PEM,
        srlz.PublicFormat.SubjectPublicKeyInfo,
    )
    return data.decode()
