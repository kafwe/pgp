import platform
import socket
import subprocess
import os
from authenticity.certificate import Certificate, load_certificate
from communication import ca_server
from communication.client import (
    FROM_LENGTH_BYTES,
    Client,
    apply_certificate,
    start as start_client,
)
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
    certificate = _load_certificate(private_key, username)
    if certificate is None:
        return
    client = _start(username, private_key, server_public_key)
    if client is None:
        return

    while not client.isShutdown:
        # TODO: Add public_key exchange. Currently assuming all users have all public_keys
        print(
            """
Options:
    Send Image (s)
    Request Certificate (c)
    List Contacts (l)
    View Images (i)
    Quit(q)
            """
        )
        choice = input()
        if choice == "s":
            _choice_send(client)
        elif choice == "p":
            _choice_request(client)
        elif choice == "i":
            _choice_image(username)
        elif choice == "q":
            client.shutdown()
            return
        # TODO add other options


def _choice_send(client: Client):
    username = client.username
    dir = f"images/{username}"
    if not os.path.exists(dir):
        os.makedirs(dir)
    if len(os.listdir(dir)) == 0:
        print(
            f"You have no images in your image folder. To send images, add images to images/{username}"
        )
        return
    peer = input("Enter recepient username\n")
    try:
        pub_key = load_public_key(f"{username}/{peer}")
    except OSError:
        _request_certificate(client, peer)
        return

    image_path = input(
        f"Enter the path of the image file (relative to images/{username}/):\n"
    )
    image = _load_image(f"images/{username}/{image_path}")
    if image is None:
        return
    caption = input("Enter a caption for the image: \n")
    client.send_image(peer, pub_key, image, caption)


def _choice_request(client: Client):
    peer = input("Enter recepient username\n")
    client.request_certificate(peer)
    print(f"Certificate request sent to {peer}")


def _choice_image(username: str):
    dir = f"images/{username}"
    if not os.path.exists(dir):
        print(f"No images saved for user {username}")
        return
    files = sorted(os.listdir(dir))
    print("Listing Images:")
    print(_format_file_names(files))
    print("Type an Image ID to open it:")
    try:
        choice = int(input())
        file = files[choice]
        print(f"Opening {file}...")
        _open_in_default_app(f"{dir}/{file}")
    except Exception:
        print("Invalid ID")


def _format_file_names(files: list[str]) -> str:
    formatted: list[list[str]] = []
    formatted.append(["ID", "Date", "Time", "From", "Caption"])
    formatted.append(["--", "----", "----", "----", "-------"])
    for i, f in enumerate(files):
        split = f.split("--")
        if len(split) != 4:
            continue
        split.insert(0, str(i))
        formatted.append(split)
    max_widths: list[int] = [0] * 5
    for row in formatted:
        for c, col in enumerate(row):
            max_widths[c] = max(max_widths[c], len(col))
    for r, row in enumerate(formatted):
        for c, col in enumerate(row):
            diff = max_widths[c] - len(col)
            lpad = str((diff // 2) * " ")
            rpad = lpad
            if diff % 2 == 1:
                lpad = lpad + " "
            formatted[r][c] = lpad + col + rpad
    return "\n".join([" | ".join(row) for row in formatted])


# Taken from: https://stackoverflow.com/questions/434597/open-document-with-default-os-application-in-python-both-in-windows-and-mac-os
def _open_in_default_app(path: str):
    # macOS
    if platform.system() == "Darwin":
        subprocess.call(("open", path))
    # Windows
    elif platform.system() == "Windows":
        os.startfile(path)
    # Linux
    else:
        subprocess.call(("xdg-open", path))


def _start(
    username: str, private_key: PrivateKey, server_public_key: PublicKey
) -> Client | None:
    address = input("What is the mail server address? (default = localhost)\n")
    if address == "":
        address = None

    port = input("What is the mail server port? (default = 9999)\n")
    if port == "":
        port = int(9999)
    try:
        port = int(port)
    except Exception as e:
        log(str(e))
        print("Invalid port")
        return
    try:
        client = start_client(username, private_key, server_public_key, address, port)
    except Exception as e:
        print(
            "Unable to connect to server. Are you sure that's the right address and port? Maybe the server is offline"
        )
        log(str(e))
    return client


def _request_certificate(client: Client, peer: str):
    choice = input(
        "You do not have this user's public key saved. Request certificate from server? (y/n)\n"
    )
    if choice == "y":
        client.request_certificate(peer)
        print("Request sent. Try sending again once you have received the key")


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
        # TODO: add password protection
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


def _load_certificate(private_key: PrivateKey, username: str) -> Certificate | None:
    try:
        cert = load_certificate(f"{username}/certificate")
        return cert
    except Exception as e:
        log(str(e))
        print(
            f"Unable to load Certificate for {username}. Would you like to request one from the CA Server?"
        )
        choice = input()
        if choice == "y":
            print("What")
            ca = _connect_ca()
            if ca is None:
                return None
            certificate = apply_certificate(
                ca, private_key.get_public_key(), username.encode()
            )
            if certificate is None:
                return
            return certificate
        else:
            return None


def _connect_ca() -> socket.socket | None:
    address = input("What is the CA server address? (default = localhost)\n")
    if address == "":
        address = None

    port = input("What is the CA server port? (default = 9999)\n")
    if port == "":
        port = int(9998)
    try:
        port = int(port)
    except Exception as e:
        log(str(e))
        print("Invalid port")
        return

    if address == "" or address is None:
        address = socket.gethostname()
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((address, port))
    except Exception as e:
        print(
            "Unable to connect to server. Are you sure that's the right address and port? Maybe the server is offline"
        )
        log(str(e))
