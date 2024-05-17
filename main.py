import shutil
import os
import sys
import threading
from cli.client_cli import client_cli
from cli.server_cli import mail_server_cli, ca_server_cli
import log
from confidentiality.asymetric import (
    generate_key_pair,
    load_private_key,
    load_public_key,
)


def main():
    log.configure()
    log.log("Logging enabled")

    if "--gen" in sys.argv:
        i = sys.argv.index("--gen")
        username = sys.argv[i + 1]
        password = sys.argv[i + 2] if len(sys.argv) > i + 2 else None
        gen(username, password)
        return

    if "--reset" in sys.argv:
        os.remove("certificates.db")
        shutil.rmtree("keys")
        os.mkdir("keys")

    choice = input("Mail Server (1) CA Server (2) or Client (3)?\n")

    if choice == "1":
        mail_server_cli()
    elif choice == "2":
        ca_server_cli()
    elif choice == "3":
        client_cli()


def gen(username: str, password: str | None):
    private, public = generate_key_pair()
    dir = f"keys/{username}"
    if not os.path.exists(dir):
        os.makedirs(dir)
    private.save(f"{username}/private", password)
    public.save(f"{username}/public")
    if username == "ca":
        public.save("ca_public_key")

    log.log(f"Generated public and private keys for: {username}")


if __name__ == "__main__":
    main()
