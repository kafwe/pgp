import threading
import communication.communication as comms
import communication.messages as msg
import log


def main():
    log.configure()
    choice = input("Do you want to host (1) or to connect (2): ")

    if choice == "1":
        client = comms.start_server()
    elif choice == "2":
        client = comms.start_client()
    else:
        exit()

    threading.Thread(target=msg.sending_messages, args=(client,)).start()
    threading.Thread(target=msg.receiving_messages, args=(client,)).start()


if __name__ == "__main__":
    main()
