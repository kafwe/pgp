import socket
import threading
import communication.communication as comms

import logging
import sys

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s: \n%(message)s"
)
logger = logging.getLogger(__name__)

if "--debug" in sys.argv:
    log_level = logging.DEBUG
else:
    log_level = logging.CRITICAL


def main():
    choice = input("Do you want to host (1) or to connect (2): ")

    # Server just made to accept the connection
    if choice == "1":
        server = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )  # AF_INET specifies IPV4, SOCK_STREAM specifies a TCP connection
        # server.bind(("196.24.152.20", 9999))
        server.bind((socket.gethostname(), 9999))
        server.listen()
        client, _ = server.accept()

    elif choice == "2":
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(
            (socket.gethostname(), 9999)
        )  # specify the IP of the machine you're connecting to
        # client.connect(("196.24.152.20", 9999))

    else:
        exit()

    threading.Thread(target=comms.sending_messages, args=(client,)).start()
    threading.Thread(target=comms.receiving_messages, args=(client,)).start()


if __name__ == "__main__":
    main()

### Structure of the Message ###
""" A caption + the image data encoded as a string

So the app must first prompt the user to select/name a file.
Then it must prompt them to write a caption for the image.

HeaderSize is fixed at 11 bytes - 3 bytes for caption length, 8 bytes for image data length
"""
