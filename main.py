import base64
import socket
import threading

# instead of rsa library use pip install cryptography that Jordy sent

# Creating the TCP connection
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


# Sending the message
def sending_messages(c):
    while True:
        # Getting image information
        image_path = input(
            "Enter the path of the image file:\n"
        )  # Ask the user for the image file path

        with open(image_path, "rb") as file:
            image_data = file.read()  # Read the image file

        image_data_base64 = base64.b64encode(image_data).decode(
            "utf-8"
        )  # Convert image data to base64
        image_data_base64_padded = image_data_base64 + "=" * (
            (4 - len(image_data_base64) % 4) % 4
        )  # Add padding if necessary (needed for encoding in base64)

        image_data_length = len(
            image_data_base64_padded
        )  # length of the image data to pass into packet header

        # Getting caption information
        caption = input("Enter a caption for the image: ")  # Get caption from user

        caption_length = len(
            caption
        )  # length of the caption to pass into packet header

        # Create packet
        message_header = f"{caption_length:<3}{image_data_length:<8}"  # 3 bytes for caption length, 8 for image size
        message = (
            caption + image_data_base64_padded
        )  # full message is made up of caption and image
        packet = message_header + message
        # print(packet)

        # Send packet to reciever
        c.send(packet.encode())
        # print("Image sent")


def receiving_messages(c):
    header_recieved = False
    full_message = ""

    while True:
        # Receive message
        message = c.recv(1024).decode()  # recieve message and decode it out of bits

        if not header_recieved:
            print("New message recieved")
            caption_length = int(message[0:3])
            image_data_length = int(message[3:11])

            print(f"Caption is of length {caption_length}")
            print(f"Image data is of length {image_data_length}")

            full_message += message[
                11:
            ]  # add to the message (not including the header)
            header_recieved = True  # no longer a new message

        else:
            full_message += message

        if len(full_message) == (
            caption_length + image_data_length
        ):  # Once you've recieved the full message, split the caption and image
            caption = full_message[:caption_length]
            image_data = base64.b64decode(
                full_message[caption_length:].encode()
            )  # Convert base64 back to image data

            header_recieved = False  # You have recieved the full message, so now wait for a new message
            full_message = ""

            print(f"Image caption: {caption}")
            save_image(image_data)  # save the image as a file


def save_image(image_data):
    # Save the image
    with open("received_image.jpg", "wb") as file:
        file.write(image_data)

    print(f"Image saved as 'received_image.jpg'")


threading.Thread(target=sending_messages, args=(client,)).start()
threading.Thread(target=receiving_messages, args=(client,)).start()


### Structure of the Message ###
""" A caption + the image data encoded as a string

So the app must first prompt the user to select/name a file.
Then it must prompt them to write a caption for the image.

HeaderSize is fixed at 11 bytes - 3 bytes for caption length, 8 bytes for image data length
"""


# MAC and

### This code creates and stores a key pair. Once you have done this though ###
### you can then from then on simply load in your keys ###

# # Create a key pair (public and private)
# publicKey, privateKey = rsa.newkeys(1024)

# # Store the two keys (in a .pem file)
# with open("public.pem", "wb") as file:
#     file.write(publicKey.save_pkcs1("PEM"))

# with open("private.pem", "wb") as file:
#     file.write(privateKey.save_pkcs1("PEM"))


### We just need to load in our key pair now from where we store it and can then use it ###
# with open("public.pem", "rb") as file:
#     publicKey = rsa.PublicKey.load_pkcs1(file.read())

# with open("private.pem", "rb") as file:
#     privateKey = rsa.PrivateKey.load_pkcs1(file.read())


# ### Sending a message ###

# message = "Hello my favorite people" # Create message
# messageInBytes = message.encode() # Encode the message to bytes before encrypting to ensure a standard language with no nuances

# # Create a hash from the message data
# signature = rsa.sign(messageInBytes, privateKey, "SHA-256") # Use your own private key to sign a message

# # Encrypt the actual message with the recievers public key
# otherPersonsPublicKey = "whatever"
# encryptedMessage = rsa.encrypt(messageInBytes, otherPersonsPublicKey) # Encrypt the message

# # then we send this signature + encryptedMessage over the TCP connection


# ### Recieving a message ###

# recievedFullMessage = "" # Will be recieved through the TCP connection

# # I think split up the message and the signature
# recievedSignature = recievedFullMessage[:10] # look how to do this
# recievedMessage = recievedFullMessage[10:]

# # Decrpyt the recieved message
# recievedMessagedDecrypted = rsa.decrypt(recievedMessage, privateKey) # Note the message will still in bytes after this step

# # Check authenticity (signature) of the message
# rsa.verify(recievedMessagedDecrypted, recievedSignature, otherPersonsPublicKey) # remember it's like the checksum

# # Finally change the decrypted message from bytes to actual string message
# recievedMessagedDecryptedNotInBytes = recievedMessagedDecrypted.decode() # from bytes to string

# print(recievedMessagedDecryptedNotInBytes)
