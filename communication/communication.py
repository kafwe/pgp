import base64


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
    with open("images/received_image.jpg", "wb") as file:
        file.write(image_data)

    print(f"Image saved as 'received_image.jpg'")
