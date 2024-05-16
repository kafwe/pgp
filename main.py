import sys
import threading
from cli.client_cli import client_cli
from cli.server_cli import server_cli
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

        private, public = generate_key_pair()
        private.save(f"{username}/private", password)
        public.save(f"{username}/public")

        log.log(f"Generated public and private keys for: {username}")
        return

    choice = input("Server (1) or Client (2)?\n")

    if choice == "1":
        server_cli()
    elif choice == "2":
        client_cli()
    else:
        return


if __name__ == "__main__":
    main()
