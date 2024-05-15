import sys
import threading
from confidentiality.asymetric import (
    generate_key_pair,
    load_private_key,
    load_public_key,
)
from communication.server import start as start_server
from communication.client import start as start_client
import log


def main():
    log.configure()
    log.log("Logging enabled")

    if "--gen" in sys.argv:
        i = sys.argv.index("--gen")
        username = sys.argv[i + 1]
        password = sys.argv[i + 2] if len(sys.argv) > i + 2 else None

        private, public = generate_key_pair()
        private.save(f"{username}/private", password)
        public.save(f"{username}/public")

        log.log(f"Generated public and private keys for: {username}")
        return

    port = 9999
    if "--port" in sys.argv:
        i = sys.argv.index("--port") + 1
        port = int(sys.argv[i])

    log.log(f"Using server port {port}")

    choice = input("Server (1) or Client (2)?")

    if choice == "1":
        _server_cli(port)
    elif choice == "2":
        _client_cli(port)
    else:
        return


def _server_cli(port: int):
    shutdown, online = start_server(port)
    while True:
        choice = input("Type (ls) to list online users or (q) to quit")
        if choice == "q":
            log.log("Shutting down server")
            shutdown()
            break
        if choice == "ls":
            print(online())


def _client_cli(port: int):
    username = input("What is your username?")
    address = input("What is the server address? (default = localhost)")
    if address == "":
        address = None
    send = start_client(username, address, port)

    while True:
        # TODO: Add public_key exchange. Currently assuming all users have all public_keys
        # TODO: Add input validation
        choice = input("Send Image (1), Quit(2),")
        if choice == "1":
            peer = input("Enter recepient username")
            pub_key = load_public_key(f"{username}/{peer}")
            image_path = input("Enter the path of the image file:\n")
            image = _load_image(image_path)
            caption = input("Enter a caption for the image: ")
            send(peer, pub_key, image, caption)
        elif choice == "2":
            return


def _load_image(image_path: str) -> bytes:
    with open(image_path, "rb") as file:
        image_data = file.read()  # Read the image file
    return image_data


if __name__ == "__main__":
    main()
