import base64
import socket

### Structure of the Message ###
"""
A caption + the image data encoded as a string

So the app must first prompt the user to select/name a file.
Then it must prompt them to write a caption for the image.

HeaderSize is fixed at 11 bytes - 3 bytes for caption length, 8 bytes for image data length
"""

# Number of bytes dedicated to stating the caption's length
CAPTION_LENGTH_BYTES = 2  # Max size = ~1KB (1000 characters)
# Number of bytes dedicated to stating the images's length
IMAGE_LENGTH_BYTES = 4  # Max size = ~500mb


def sending_messages(c: socket.socket):
    while True:
        image = _get_image_from_user()
        caption = input("Enter a caption for the image: ")

        header = _create_header(len(caption), len(image))
        message = caption.encode() + image
        packet = header + message

        # Send packet to reciever
        c.send(packet)


def _create_header(caption_length: int, image_length: int) -> bytes:
    # TODO: Error handling for caption/image that is too large
    encoded_caption_len = caption_length.to_bytes(CAPTION_LENGTH_BYTES, "big")
    encoded_image_len = image_length.to_bytes(IMAGE_LENGTH_BYTES, "big")
    return encoded_caption_len + encoded_image_len


def _get_image_from_user() -> bytes:
    image_path = input("Enter the path of the image file:\n")

    with open(image_path, "rb") as file:
        image_data = file.read()  # Read the image file
    return image_data


# def _format_image_data(data: bytes) -> bytes:
#     image_data_base64 = base64.b64encode(data).decode("utf-8")
#     # Add padding if necessary (needed for encoding in base64)
#     image_data_base64_padded = image_data_base64 + "=" * (
#         (4 - len(image_data_base64) % 4) % 4
#     )


def receiving_messages(c: socket.socket):
    while True:
        # Receive message
        message = c.recv(1024)  # recieve message and decode it out of bits

        print("New message recieved")
        caption_length = int.from_bytes(message[:CAPTION_LENGTH_BYTES], "big")
        message = message[CAPTION_LENGTH_BYTES:]

        image_length = int.from_bytes(message[:IMAGE_LENGTH_BYTES], "big")
        message = message[IMAGE_LENGTH_BYTES:]

        print(f"Caption is of length {caption_length}")
        print(f"Image data is of length {image_length}")

        # Once you've recieved the full message, split the caption and image
        caption = message[:caption_length]
        image = message[caption_length:]

        print(f"Image caption: {caption}")
        # TODO: Give the user an option to choose file_name
        save_image(image, "received_image.jpg")  # save the image as a file


def save_image(image_data: bytes, file_name: str):
    # Save the image
    with open(f"images/{file_name}", "wb") as file:
        file.write(image_data)

    print(f"Image saved as {file_name}")


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
