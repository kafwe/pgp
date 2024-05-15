import os
from communication.client import Client, start as start_client
from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    generate_key_pair,
    load_private_key,
    load_public_key,
)
from log import log


def client_cli():
    username = input("What is your username?\n")
    private_key, server_public_key = _load_keys(username)
    if private_key is None or server_public_key is None:
        return
    client = _start(username, private_key, server_public_key)
    if client is None:
        return

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
            if image is None:
                continue
            caption = input("Enter a caption for the image: \n")
            client.send_image(peer, pub_key, image, caption)
        elif choice == "q":
            client.shutdown()
            return
        # TODO add other options


def _start(
    username: str, private_key: PrivateKey, server_public_key: PublicKey
) -> Client | None:
    address = input("What is the server address? (default = localhost)\n")
    if address == "":
        address = None

    port = input("What is the server port? (default = 9999)\n")
    try:
        port = int(port)
    except Exception as e:
        log(str(e))
        print("Invalid port.")
    if port == "":
        port = int(9999)

    try:
        client = start_client(username, private_key, server_public_key, address, port)
    except Exception as e:
        print(
            "Unable to connect to server. Are you sure that's the right address and port? Maybe the server is offline."
        )
        log(str(e))
    return client


def _request_certificate(client: Client, peer: str):
    choice = input(
        "You do not have this user's public key saved. Request certificate from server? (y/n)\n"
    )
    if choice == "y":
        client.request_certificate(peer)
        print("Request sent. Try sending again once you have received the key.")


def _load_image(image_path: str) -> bytes | None:
    try:
        with open(image_path, "rb") as file:
            image_data = file.read()  # Read the image file
    except Exception as e:
        print(f"Unable to read {image_path}. Are you sure that is the correct file?")
        log(str(e))
        return None
    return image_data


def _load_keys(username: str) -> tuple[PrivateKey | None, PublicKey | None]:
    try:
        pri_key = load_private_key(f"{username}/private")
    except Exception as e:
        log(str(e))
        print(
            f"Unable to load keys for {username}. Would you like to generate some? (y/n)"
        )
        choice = input()
        if choice == "y":
            pri_key, pub_key = generate_key_pair()
            dir = f"keys/{username}"
            if not os.path.exists(dir):
                os.makedirs(dir)
            pri_key.save(f"{username}/private")
            pub_key.save(f"{username}/public")
        else:
            return None, None
    try:
        server_pub_key = load_public_key("server/public")
    except Exception as e:
        log(str(e))
        print(
            "Unable to load server's public key. Are you sure you have it saved as keys/server/public ?"
        )

    server_pub_key = load_public_key("server/public")
    log("Succesfully loaded private and public keys")
    return pri_key, server_pub_key
