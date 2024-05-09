import logging

from tests.utils import (
    gen_and_save_keys,
    read_private_keys,
    read_public_keys,
    show_private_key,
    show_public_key,
)

logger = logging.getLogger(__name__)


def test_key_saving() -> bool:
    logger.debug("Generating keys:")
    (a_private, a_public), (b_private, b_public) = gen_and_save_keys()
    a_private = show_private_key(a_private)
    b_private = show_private_key(b_private)
    a_public = show_public_key(a_public)
    b_public = show_public_key(b_public)

    logger.debug("\nPrivate")
    logger.debug("\nalice\n")
    logger.debug(a_private)
    logger.debug("\nbob\n")
    logger.debug(b_private)

    logger.debug("\nPublic")
    logger.debug("\nalice\n")
    logger.debug(a_public)
    logger.debug("\nbob\n")
    logger.debug(b_public)

    logger.debug("\nReading them in (and decrypting):")

    logger.debug("\nPrivate")
    logger.debug("\nalice\n")
    a_private_r, b_private_r = read_private_keys()
    a_private_r = show_private_key(a_private_r)
    b_private_r = show_private_key(b_private_r)

    logger.debug(a_private_r)
    logger.debug("\nbob\n")
    logger.debug(b_private_r)

    a_public_r, b_public_r = read_public_keys()
    a_public_r = show_public_key(a_public_r)
    b_public_r = show_public_key(b_public_r)
    logger.debug("\nPublic")
    logger.debug("\nalice\n")
    logger.debug(a_public_r)
    logger.debug("\nbob\n")
    logger.debug(b_public_r)

    return (
        a_private == a_private_r
        and b_private == b_private_r
        and a_public == a_public_r
        and b_public == b_public_r
    )


def test_message_encryption() -> bool:
    a_private, b_private = read_private_keys()
    a_public, b_public = read_public_keys()
