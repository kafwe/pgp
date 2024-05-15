from confidentiality.symetric import SecretKey
from log import log
import confidentiality.pgp as pgp

from tests.utils import (
    gen_and_save_keys,
    read_private_keys,
    read_public_keys,
    show_private_key,
    show_public_key,
)


def test_key_saving() -> bool:
    log("Generating keys:")
    (a_private, a_public), (b_private, b_public) = gen_and_save_keys()
    a_private = show_private_key(a_private)
    b_private = show_private_key(b_private)
    a_public = show_public_key(a_public)
    b_public = show_public_key(b_public)

    log("\nPrivate")
    log("\nalice\n")
    log(a_private)
    log("\nbob\n")
    log(b_private)

    log("\nPublic")
    log("\nalice\n")
    log(a_public)
    log("\nbob\n")
    log(b_public)

    log("\nReading them in (and decrypting):")

    log("\nPrivate")
    log("\nalice\n")
    a_private_r, b_private_r = read_private_keys()
    a_private_r = show_private_key(a_private_r)
    b_private_r = show_private_key(b_private_r)

    log(a_private_r)
    log("\nbob\n")
    log(b_private_r)

    a_public_r, b_public_r = read_public_keys()
    a_public_r = show_public_key(a_public_r)
    b_public_r = show_public_key(b_public_r)
    log("\nPublic")
    log("\nalice\n")
    log(a_public_r)
    log("\nbob\n")
    log(b_public_r)

    return (
        a_private == a_private_r
        and b_private == b_private_r
        and a_public == a_public_r
        and b_public == b_public_r
    )


def test_asym_encryption() -> bool:
    a_private, b_private = read_private_keys()
    a_public, b_public = read_public_keys()
    message = b"top_secret_message"
    log("Encrypting a")
    a_encrypted = a_public.encrypt(message)
    log("Encrypting b")
    b_encrypted = b_public.encrypt(message)
    log("Decrypting a")
    a_decrypted = a_private.decrypt(a_encrypted)
    log("Decrypting b")
    b_decrypted = b_private.decrypt(b_encrypted)
    return a_decrypted == message and b_decrypted == message


def test_sym_encryption() -> bool:
    sk = SecretKey()
    message = b"top_secret_message"
    log("Encrypting")
    encrypted = sk.encrypt(message)
    kiv = sk.kiv
    log("Decrypting without transfer")
    decrypted1 = sk.decrypt(encrypted)
    log(decrypted1.decode())
    log("Decrypting with transfer")
    decrypted2 = SecretKey(kiv).decrypt(encrypted)
    log(decrypted1.decode())
    return decrypted1 == message and decrypted2 == message


def test_pgp_encryption() -> bool:
    a_private, b_private = read_private_keys()
    a_public, b_public = read_public_keys()
    message = b"top_secret_message"
    log("Encrypting a")
    a_encrypted = pgp.pgp_encrypt(message, a_public)
    log("Encrypting b")
    b_encrypted = pgp.pgp_encrypt(message, b_public)
    log("Decrypting a")
    a_decrypted = pgp.pgp_decrypt(a_encrypted, a_private)
    log("Decrypting b")
    b_decrypted = pgp.pgp_decrypt(b_encrypted, b_private)
    return a_decrypted == message and b_decrypted == message
