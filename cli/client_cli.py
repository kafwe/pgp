import os
import platform
import subprocess

from authenticity.certificate import Certificate
from cli.certificate_cli import (
    auto_request_certificate,
    connect_ca,
    load_certificate,
    request_certificate,
)
from communication.client import (
    Client,
)
from communication.client import (
    start as start_client,
)
from communication.constants import SUPPORTED_TYPES
from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    generate_key_pair,
    load_private_key,
    load_public_key,
)
from log import log


def client_cli():
    username = input("\nWhat is your username?\n")
    keys = _load_keys(username)
    if keys is None:
        return
    private_key, server_public_key, ca_public_key = keys
    certificate = load_certificate(private_key, username)
    if certificate is None:
        return
    client = _start(
        username, private_key, certificate, server_public_key, ca_public_key
    )
    if client is None:
        return

    while not client.isShutdown:
        print(
            f"""
{username}
Options:
    Send Image (s)
    Request Certificate (c)
    View Images (i)
    Quit(q)

            """
        )
        choice = input()
        if choice == "s":
            _choice_send(client)
        elif choice == "c":
            _choice_request(client)
        elif choice == "i":
            _choice_image(username)
        elif choice == "q":
            client.shutdown()
            return


def _start(
    username: str,
    private_key: PrivateKey,
    certificate: Certificate,
    server_public_key: PublicKey,
    ca_public_key: PublicKey,
) -> Client | None:
    address = input("\nWhat is the mail server address? (default = localhost)\n")
    if address == "":
        address = None

    port = input("\nWhat is the mail server port? (default = 9999)\n")
    if port == "":
        port = int(9999)
    try:
        port = int(port)
    except Exception as e:
        log(str(e))
        print("Invalid port")
        return
    try:
        client = start_client(
            username,
            private_key,
            certificate,
            server_public_key,
            ca_public_key,
            address,
            port,
        )
    except Exception as e:
        print(
            "Unable to connect to server. Are you sure that's the right address and port? Maybe the server is offline"
        )
        log(str(e))
        return None
    return client


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
    peer = input("\nEnter recepient username\n")
    try:
        pub_key = load_public_key(f"{username}/{peer}")
    except OSError:
        pub_key = auto_request_certificate(client.ca_public_key, username, peer)
        if pub_key is None:
            return

    image_path = input(
        f"Enter the path of the image file (relative to images/{username}/):\n"
    )
    try:
        file_type = image_path.split(".")[1]
    except IndexError:
        file_type = "None"

    if file_type not in SUPPORTED_TYPES:
        print(
            f"Cannot send file of type {file_type}, must be in {",".join(SUPPORTED_TYPES)}"
        )
        return

    image = _load_image(f"images/{username}/{image_path}")
    if image is None:
        return
    caption = input("Enter a caption for the image: \n")
    print("Sending...")
    client.send_image(peer, pub_key, image, file_type, caption)


def _choice_request(client: Client):
    peer = input("\nEnter peer's username\n")
    if peer == "":
        return
    ca = connect_ca()
    if ca is None:
        return None
    cert = request_certificate(client.ca_public_key, ca, peer.encode())
    if cert is None:
        return None
    cert.save_public_key(f"{client.username}/{peer}")


def _choice_image(username: str):
    dir = f"images/{username}"
    if not os.path.exists(dir):
        print(f"No images saved for user {username}")
        return
    files = sorted(os.listdir(dir))
    print("\nListing Images:")
    print(_format_file_names(files))
    print("Type an Image ID to open it:")
    try:
        choice = int(input())
        file = files[choice]
        print(f"Opening {file}...")
        _open_in_default_app(f"{dir}/{file}")
    except Exception:
        print("Invalid ID")
    print()


def _format_file_names(files: list[str]) -> str:
    formatted: list[list[str]] = []
    formatted.append(["ID", "Date", "Time", "From", "Caption"])
    formatted.append(["--", "----", "----", "----", "-------"])
    for i, f in enumerate(files):
        split = f.split("--")
        if len(split) != 4:
            continue
        split.insert(0, str(i))
        caption = split.pop().split(".")[0]
        if len(caption) > 30:
            caption = caption[:30] + "..."
        split.append(caption)
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


def _load_image(image_path: str) -> bytes | None:
    try:
        with open(image_path, "rb") as file:
            image_data = file.read()  # Read the image file
    except Exception as e:
        print(f"Unable to read {image_path}. Are you sure that is the correct file?")
        log(str(e))
        return None
    return image_data


def auto_gen_keys(username: str) -> tuple[PrivateKey, PublicKey] | None:
    print(f"Unable to load keys for {username}. Would you like to generate some? (y/n)")
    # TODO: add password protection
    choice = input()
    if choice == "y":
        pri_key, pub_key = generate_key_pair()
        dir = f"keys/{username}"
        if not os.path.exists(dir):
            os.makedirs(dir)
        pri_key.save(f"{username}/private")
        pub_key.save(f"{username}/public")
        return pri_key, pub_key
    else:
        return None


def _load_keys(
    username: str,
) -> tuple[PrivateKey, PublicKey, PublicKey] | None:
    try:
        pri_key = load_private_key(f"{username}/private")
    except Exception as e:
        log(str(e))
        res = auto_gen_keys(username)
        if res is None:
            return None
        pri_key, _ = res
    try:
        ca_pub_key = load_public_key("ca_public_key")
    except Exception as e:
        log(str(e))
        print("Unable to load CA's public key from keys/ca_public_key")
        return None
    try:
        server_pub_key = load_public_key(f"{username}/server")
    except Exception as e:
        log(str(e))
        server_pub_key = auto_request_certificate(ca_pub_key, username, "server")
        if server_pub_key is None:
            return None

    return pri_key, server_pub_key, ca_pub_key
