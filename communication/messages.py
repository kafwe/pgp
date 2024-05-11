from confidentiality.asymetric import PrivateKey, PublicKey
from log import log
import socket
import confidentiality.pgp as pgp

### Structure of the Message ###
"""
A caption + the image data encoded as a string

So the app must first prompt the user to select/name a file.
Then it must prompt them to write a caption for the image.

HeaderSize is fixed at 11 bytes - 3 bytes for caption length, 8 bytes for image data length
"""

# Number of bytes dedicated to stating the caption's length
CAPTION_LENGTH_BYTES = 2  # Max size = ~1KB (1000 characters)


def send(c: socket.socket, peer_public_key: PublicKey):
    while True:
        image = _get_image_from_user()
        caption = input("Enter a caption for the image: ")
        header = _create_header(len(caption))
        message = caption.encode() + image
        packet = header + message

        encrypted = pgp.pgp_encrypt(packet, peer_public_key)
        # Send packet to reciever
        c.send(encrypted)


def receive(c: socket.socket, private_key: PrivateKey):
    while True:
        encrypted = _chunk(c)
        print("New message recieved")

        decrypted = pgp.pgp_decrypt(encrypted, private_key)

        caption_length, message = _split_header_message(decrypted)

        # Once you've recieved the full message, split the caption and image
        caption = message[:caption_length].decode()
        image = message[caption_length:]

        print(f"Image caption: {caption}")
        # TODO: Give the user an option to choose file_name
        _save_image(image, "received_image.jpg")  # save the image as a file


def _create_header(caption_length: int) -> bytes:
    # TODO: Error handling for caption that is too large
    # TODO: Add MAC?
    encoded_caption_len = caption_length.to_bytes(CAPTION_LENGTH_BYTES, "big")
    return encoded_caption_len


def _split_header_message(data: bytes) -> tuple[int, bytes]:
    caption_length = int.from_bytes(data[:CAPTION_LENGTH_BYTES], "big")
    log(f"Caption is of length {caption_length}")
    data = data[CAPTION_LENGTH_BYTES:]

    message = data
    log(f"Message data is of length {len(message)}")

    return caption_length, message


def _chunk(c: socket.socket) -> bytes:
    message: bytes = b""
    while True:
        chunk = c.recv(1024)
        log(f"Chunk:{chunk}")
        message += chunk
        if len(chunk) < 1024:
            log("Returning")
            break
    return message


def _get_image_from_user() -> bytes:
    image_path = input("Enter the path of the image file:\n")

    with open(image_path, "rb") as file:
        image_data = file.read()  # Read the image file
    return image_data


def _save_image(image_data: bytes, file_name: str):
    # Save the image
    with open(f"images/{file_name}", "wb") as file:
        file.write(image_data)

    print(f"Image saved as {file_name}")
