import sys
import threading
import communication.communication as comms
import communication.messages as msg
from confidentiality.asymetric import load_private_key, load_public_key
import log


def main():
    port = 9999
    if "--port" in sys.argv:
        i = sys.argv.index("--port") + 1
        port = int(sys.argv[i])

    log.configure()
    choice = input("Do you want to host (1) or to connect (2): ")

    if choice == "1":
        client = comms.start_server(port)
        # NOTE: This is temporary. This should be handled by certificates in future
        private_key_f = "demo/Alice_private_key"
        public_key_f = "demo/Bob_public_key"
    elif choice == "2":
        client = comms.start_client(port)
        # NOTE: This is temporary. This should be handled by certificates in future
        private_key_f = "demo/Bob_private_key"
        public_key_f = "demo/Alice_public_key"
    else:
        exit()

    # NOTE: This is temporary. This should be handled by certificates in future
    peer_public_key = load_public_key(public_key_f)
    private_key = load_private_key(private_key_f, "secure_password")

    threading.Thread(target=msg.send, args=(client, peer_public_key)).start()
    threading.Thread(target=msg.receive, args=(client, private_key)).start()


if __name__ == "__main__":
    main()
