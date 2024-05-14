import socket
import threading
from datetime import datetime
from typing import Callable

import confidentiality.pgp as pgp
from communication.chunk import chunk
from communication.server import CERTIFICATE_LENGTH_BYTES
from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    load_private_key,
    load_public_key,
    load_public_key_bytes,
)
from log import log

# Number of bytes dedicated to stating the caption's length
CAPTION_LENGTH_BYTES = 2  # Max size = ~65536 characters
# Number of bytes dedicated to stating the destination username length
DEST_LENGTH_BYTES = 1  # Max size = 256 characters
# Number of bytes dedicated to stating the sender's username length
FROM_LENGTH_BYTES = 1  # Max size = 256 characters


class Client:
    private_key: PrivateKey
    server_socket: socket.socket
    server_public_key: PublicKey
    username: str
    certificate: bytes

    def __init__(
        self,
        server_socket: socket.socket,
        private_key: PrivateKey,
        server_public_key: PublicKey,
        username: str,
        certificate: bytes,
    ):
        self.private_key = private_key
        self.server_socket = server_socket
        self.server_public_key = server_public_key
        self.username = username
        self.certificate = certificate

    def receive(self) -> bool:
        data = chunk(self.server_socket)
        if data is None:
            return False
        encrypted = data
        print("New message recieved")

        decrypted = pgp.pgp_decrypt(encrypted, self.private_key)

        caption_length, from_length, message = _split_header_message(decrypted)

        # Once you've recieved the full message, split the caption and image
        caption = message[:caption_length].decode()
        message = message[caption_length:]
        sender = message[from_length:]
        image = message[from_length:]

        print(f"From: {sender}")
        print(f"Image caption: {caption}")
        # TODO: Give the user an option to choose file_name
        _save_image(image, sender.decode(), caption)
        return True

    def send(
        self, peer_username: str, peer_public_key: PublicKey, image: bytes, caption: str
    ):
        header = self._create_header(caption)
        encrypted = pgp.pgp_encrypt(header + image, peer_public_key)

        dest_bytes = peer_username.encode()
        dest_encrypted = pgp.pgp_encrypt(dest_bytes, self.server_public_key)
        dest_len = len(dest_encrypted).to_bytes(DEST_LENGTH_BYTES, "big")
        # Send packet to reciever
        self.server_socket.send(dest_len + dest_encrypted + encrypted)

    def _create_header(self, caption: str) -> bytes:
        # TODO: Error handling for caption that is too large
        # TODO: Add MAC?
        encoded_caption_len = len(caption).to_bytes(CAPTION_LENGTH_BYTES, "big")
        encoded_sender_len = len(self.username).to_bytes(CAPTION_LENGTH_BYTES, "big")

        return (
            encoded_caption_len
            + encoded_sender_len
            + encoded_caption_len
            + caption.encode()
        )

    def login(self) -> bool:
        received = self.server_socket.recv(1024)
        random = received[:8]
        sig = received[8:]
        valid = self.server_public_key.verify(random, sig)
        if not valid:
            print("WARNING: Server is compramised. Invalid signature.")
            return False

        my_sig = self.private_key.sign(random)
        cert_len = int.to_bytes(len(self.certificate), CERTIFICATE_LENGTH_BYTES, "big")
        msg = cert_len + self.certificate + my_sig
        self.server_socket.send(msg)
        return True


def _split_header_message(data: bytes) -> tuple[int, int, bytes]:
    # TODO: Error handling for caption that is too large
    # TODO: Add MAC?
    caption_length = int.from_bytes(data[:CAPTION_LENGTH_BYTES], "big")
    log(f"Caption is of length {caption_length}")
    data = data[CAPTION_LENGTH_BYTES:]

    from_length = int.from_bytes(data[:FROM_LENGTH_BYTES], "big")
    data = data[FROM_LENGTH_BYTES:]

    message = data
    log(f"Message data is of length {len(message)}")

    return caption_length, from_length, message


def _save_image(image_data: bytes, sender: str, caption: str):
    # Save the image
    date_time = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    file_name = f"{date_time}--{sender}--{caption}"

    with open(f"images/{file_name}", "wb") as file:
        file.write(image_data)

    print(f"Image saved as {file_name}")


def start(
    username: str,
    server_address: str = socket.gethostname(),
    server_port=9999,
) -> Callable[[str, PublicKey, bytes, str], None]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((server_address, server_port))
    user = username.encode()
    user_len = len(user).to_bytes(1, "big")

    client = Client(
        server,
        load_private_key(f"{username}/private"),
        load_public_key(f"{username}/server"),
        username,
        user_len + user + load_public_key_bytes(f"{username}/public"),
    )

    threading.Thread(target=_receive_thread, args=(client,)).start()
    return client.send


def _receive_thread(client: Client):
    open = client.login()
    while open:
        open = client.receive()
