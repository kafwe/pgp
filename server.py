import socket
import threading

HEADER_LENGTH = 11  # caption length + image data length (add MAC later)
USERNAME_LENGTH = 20  # max characters allowed in username
IP = socket.gethostname()
PORT = 9999

# Create the server's socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # AF_INET specifies IPV4, SOCK_STREAM specifies a TCP connection
server_socket.bind((IP, PORT))
server_socket.listen()  # listen for incoming connections
print(f"Listening for connections on {IP}:{PORT}...")

# Store clients and messages to be sent
clients = []
'''
client structure: 
{
    "username": "user username",
    "IP": "user IP",
    "PORT" "user Port",
    "socket": socket_object     # this line stores the new socket object that is created every time the user comes online. If empty, indicates user is offline 
}
'''
message_queue = [] # List/queue of stored messages that need to be sent out
'''
message_structure:
{
  "sender": "sender username",
  "receiver": "receiver username",
  "message": "Whole encrypted message must go here"
}
'''




''' 
First message we want to recieve is the client's username who is joining the server (no encryption needed)
The next message must be the name of the receiver client - who the connected client wants to send a message to (encrypt on client side with server's own personal public key)
The next message will be the full message with absolutely all information like header and body etc. - it will 
have to be accepted until there is no packets left to recieve. But note we cannot know how much data is going to be recieved
like through the header because this message is encrypted with the reciever's public key
'''


def receive_message(client):
    while True:
        try:
            # Receive length of recipients username and the message
            lengths_message = client['socket'].recv(12)  # 2 bytes for recipient username length, 10 for message length
            # Then decrypt lengths_message using the server's Private Key and decode it from bytes   lengths_message = lengths_message.decrypt().decode() - can do this all in previous line

            receiver_uname_length = int(lengths_message[:2])
            message_length = int(lengths_message[2:])

            # Now begin to receive the receiver's username and entire message buffer by buffer
            full_message = client['socket'].recv(1024)
            while len(full_message) != (receiver_uname_length + message_length):  # I don't think this will work because our encrypted values will be a different length
                full_message += client['socket'].recv(1024) 

            
            receiver_uname = full_message[:receiver_uname_length]  # this is encrypted with the server's public key
            message = full_message[receiver_uname_length:]  # this message is encrypted with the receiver's public key

            # Then decrypt receiver_uname using the server's Private Key and decode it from bytes     
            # decrypted_receiver_uname = receiver_uname.decrypt()


            # Store this message, the receiver, and the sender (as a dictionary) in a queue/array
            #message_queue.append({'sender':sender_uname, 'receiver':decrypted_receiver_uname, 'message':message})
            
            # When the receiver later comes online, we need to traverse this array to see if there are any message that are addressed to this client, and then send it
            # But right now we can also check if the intended recipient is already online, so you can send to them immediately
            if (is_online(receiver_uname)):  # might need to change this to like decrypted_receiver_uname
                send_queued_messages(receiver_uname)

        except:
            # If client closes connection
            # Then change the clients socket object to nothing (indicating they have gone offline)
            client['socket'] = ""  # now this might not actually work because i'm using a parameter, and possibly not the original object
            # Also you might need to add this previous lines in maany other places where the client could have ended the connection
            print(f"Connection to {client['username']} at address {client['IP']} | {client['PORT']} closed")
            break
            return False
    

def is_online(username):
    for client in clients:
        if client['username'] == username:
            return client['socket'] != ""  # no socket object indicates offline


# Use this function to send a message to a receiver, given the message in the queue. This means we will need another function to traverse through the message_queue to see if there is a message addressed to the specific client who just joined.
def send_message(queued_message):
    # Find the client socket that is associated with this queued_message["receiver"].
    for client in clients:
        if (client['username'] == queued_message['receiver']):
            recipient = client
            break

    # Encode the queued_message["sender"] to bits.
    encoded_sender = queued_message['sender'].encode()  

    # Encrpyt the queued_message["sender"] with the receiver's public key.     
    #encrypted_encoded_sender = encoded_sender.encrypt()

    # sender_uname_length = length(encrypted_encoded_sender)

    # message_length = length(queued_message["message"])

    # lengths_message = f"{sender_uname_length:<2}{message_length:<10}"

    # encrypted_lengths_message = lengths_message.encrypt() - with the receiver's public key

    # First message to send is the length of the sending client's username and the message
    #recipient['socket'].send(encrypted_lengths_message)
    # Then send the sender username and message as one full message 
    #recipient['socket'].send(encrypted_encoded_sender + queued_message['message'])


# Traverse through the message queue to see if any messages are addressed to the client that just came online
def send_queued_messages(receiver_uname):
    message_count = 0

    for queued_message in message_queue[:]:  # [:] makes a copy of message_queue so can remove a message from the original message queue while traversing
        if queued_message['receiver'] == receiver_uname:            
            message_count += 1
            send_message(queued_message)  # if a message is addressed to a client who just connected, send it to them
            message_queue.remove(queued_message)  # message has now been sent and can be removed from message_queue
    
    return message_count


def receive_connections():
    # Always look for connections
    while True:  
        client_socket, address = server_socket.accept()  # Wait for an incoming connection. Return a new socket object representing the connection, and the address of the client. For IP sockets, the address info is a pair (hostaddr, port).
        
        # Check if this client exists, update socket object, store information
        exists = False
        index = 0
        for client in clients:
            if (client['IP'] == address[0] and client['PORT'] == address[1]):  # IP may be the only thing we need
                exists = True
                break
            index += 1

        # If client exists
        if (exists):  
            print(f"Connection is established with {address[0]} | {address[1]} - existing user: {clients[index]['username']}")
            client_socket.send(f"Welcome back {clients[index]['username']}".encode())  # send a welcome back {username} message - encrypt this with client's public key
            clients[index]['socket'] = client_socket  # set the socket object in clients
            print("Send/receiving messages in the message queue")
            send_queued_messages(client_socket)  # call send_queued_messages with this client's socket/ID number or something

        # If client new
        else:
            print(f"Connection is established with {address[0]} | {address[1]} - new user")
            print(f"Awaiting username")
            client_socket.send(f"Welcome new user. Please choose a username".encode())  # encrypt this with public key 
            username = client_socket.recv(USERNAME_LENGTH).decode().strip()  # ask user to provide a username and receive it - might want to decrypt this
            print(f"Username of new client: {username}")
            clients.append({'username':username, 'IP':address[0], 'PORT':address[1], 'socket':client_socket})  # add this new client to the client's list
        
        print(clients)

    
        thread = threading.Thread(target = receive_message, args=(clients[index],))  # we are passing in the client dictionary (into the array) to receive_message()
        thread.start()


if __name__ == "__main__":
    receive_connections()

