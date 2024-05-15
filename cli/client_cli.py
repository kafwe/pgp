from communication.client import Client, start as start_client
from confidentiality.asymetric import (
    generate_key_pair,
    load_private_key,
    load_public_key,
)


def client_cli(port: int):
    username = input("What is your username?\n")
    address = input("What is the server address? (default = localhost)\n")
    if address == "":
        address = None
    client = start_client(username, address, port)

    while True:
        # TODO: Add public_key exchange. Currently assuming all users have all public_keys
        # TODO: Add input validation
        choice = input(
            """
Options:
    Send Image (s)
    Request Certificate (c)
    Provide Certificate(p)
    List Contacts (l)
    Quit(q)
            """
        )
        if choice == "s":
            peer = input("Enter recepient username\n")
            try:
                pub_key = load_public_key(f"{username}/{peer}")
            except OSError:
                _request_certificate(client, peer)
                continue

            image_path = input(
                "Enter the path of the image file (relative to project_root/images):\n"
            )
            image = _load_image(f"images/{image_path}")
            caption = input("Enter a caption for the image: \n")
            client.send_image(peer, pub_key, image, caption)
        elif choice == "q":
            return
        # TODO add other options


def _request_certificate(client: Client, peer: str):
    choice = input(
        "You do not have this user's public key saved. Request certificate from server? (y/n)\n"
    )
    if choice == "y":
        client.request_certificate(peer)
        print("Request sent. Try sending again once you have received the key.")


def _load_image(image_path: str) -> bytes:
    with open(image_path, "rb") as file:
        image_data = file.read()  # Read the image file
    return image_data
