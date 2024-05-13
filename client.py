import base64
import threading
import socket
import sys

IP = socket.gethostname()
PORT = 9999

# Create your client socket and connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT)) # specify the IP of the server you're connecting to 


def receive_message():  # this we are going to need to run in a while true loop cause we nee=ver know when someone may send something
    while True: 
        try:
            # First message to receive is the length of the sender client's username and the message
            lengths_header = client_socket.recv(1024).decode()  # will probably need to decrypt this using your private key   client_socket.recv(1024).decode()
            sender_username_length = int(lengths_header[0:3])
            full_message_length = int(lengths_header[3:11])

            # Now begin to receive the sender's username and entire message buffer by buffer
            full_packet = client_socket['socket'].recv(1024)  # receive message
            while len(full_packet) != (sender_username_length + full_message_length): # I don't think this will work because our encrypted values will be a different length
                full_packet += client_socket['socket'].recv(1024) 

            # Split the received message into the sender's username and full message
            full_packet = full_packet.decrypt()
            sender_username = full_packet[:sender_username_length].decode()  # this is encrypted with the server's public key
            full_message = full_packet[sender_username_length:]  # this message is encrypted with the receiver's public key (dont decode yet cause it contains the image data which needs base 64 decoding)

            # Now split the actual message (with caption and length and image_data and length)
            caption_length = int(full_message[0:3].decode())
            image_data_length = int(full_message[3:11].decode())
            header_length = caption_length + image_data_length

            caption = full_message[header_length:caption_length].decode()
            image_data = base64.b64decode(full_message[header_length+caption_length:].encode())  # Convert base64 back to image data

            print(f'Image received from: {sender_username}')
            print(f'Image caption: {caption}')
            save_image(image_data)  # save the image as a file

            
        except:
            print(f'Connection interrupted')
            client_socket.close()
            sys.exit()


def save_image(image_data):
    # Save the image
    with open("received_image.jpg", "wb") as file:
        file.write(image_data)

    print(f"Image saved as 'received_image.jpg'")


# Messages received upon connection
welcome_message =  client_socket.recv(42).decode()  # need to decrypt this client_socket.recv(42).decrypt().decode()
print(welcome_message)

if welcome_message[8:11] == 'new': # New client to input a username
    username = input()
    client_socket.send(f'{username:<20}'.encode())  # may want to encrypt this
    
# Then we start listening to receive any messages
receive_thread = threading.Thread(target=receive_message)
receive_thread.start()

    