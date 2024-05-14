import sys
import threading
from confidentiality.asymetric import load_private_key, load_public_key
from communication.server import start as start_server
from communication.client import start as start_client
import log


def main():
    port = 9999
    if "--port" in sys.argv:
        i = sys.argv.index("--port") + 1
        port = int(sys.argv[i])

    log.configure()
    choice = input("Server (1) or Client (2)? ")

    if choice == "1":
        _server_cli(port)
    elif choice == "2":
        _client_cli(port)

    else:
        exit()


if __name__ == "__main__":
    main()


def _server_cli(port: int):
    shutdown = start_server(port)
    while True:
        if input("Type q to quit") == "q":
            shutdown()
            break


def _client_cli(port: int):
    username = input("What is your username?")
    address = input("What is the server address? (default = localhost)")
    send = start_client(username, address, port)

    while True:
        # TODO: Add public_key exchange. Currently assuming all users have all public_keys
        choice = input("Send Image (1), Quit(2),")
        if choice == "1":
            peer = input("Enter recepient username")
            pub_key = load_public_key(f"{username}/{peer}")
            image_path = input("Enter the path of the image file:\n")
            image = _load_image(image_path)
            caption = input("Enter a caption for the image: ")
            send(peer, pub_key, image, caption)
        else:
            exit()


def _load_image(image_path: str) -> bytes:
    with open(image_path, "rb") as file:
        image_data = file.read()  # Read the image file
    return image_data
