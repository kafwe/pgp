import socket
import threading
import communication.communication as comms


def main():
    choice = input("Do you want to host (1) or to connect (2): ")

    if choice == "1":
        client = comms.start_server()
    elif choice == "2":
        client = comms.start_client()
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


def start_server() -> socket.socket:
    # AF_INET specifies IPV4, SOCK_STREAM specifies a TCP connection
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((socket.gethostname(), 9999))
    server.listen()
    client, _ = server.accept()
    return client


def start_client(ip_address: str = socket.gethostname()) -> socket.socket:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip_address, 9999))
    return client
