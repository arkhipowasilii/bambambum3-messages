import socket
import sys

import select
import errno
from encrypter import Encrypter

HEADER_LENGTH = 10
#Commands
# 0 - "/e" encrypt dialog with a user
# 1 - "/u" update messages
COMMANDS = ["e", "u"]
IP = "127.0.0.1"
PORT = 1234
my_username = input("Username: ")
private_chat_username = ""
is_private_chat_accepted = False
encrypter = Encrypter()
is_check_for_foreign_public_key = False


# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
client_socket.connect((IP, PORT))

# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(False)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)


def send_message(_message: bytes):
    # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
    _message_header = f"{len(_message):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(_message_header + _message)


while True:

    # Wait for user to input a message
    if is_private_chat_accepted is False:
        message = input(f'{my_username} > ')
        enc_message = message.encode('utf-8')
    elif encrypter.foreign_public_key is not None:
        message = input(f'{my_username} -> {private_chat_username} > ')
        enc_message = encrypter.do_asym_encrypt_of_message(message.encode('utf-8'))
    else:
        message = ""
        enc_message = message

    # If message is not empty - send it
    if message.startswith("/"):
        command = message[1:]
        if command == COMMANDS[0]:
            private_chat_username = input(f'If you want to start secured dialog, enter your reciver nickname > ')
            send_message(f"{my_username} want to start private chat with {private_chat_username}.".encode('utf-8'))
        elif command == COMMANDS[1]:
            pass
    elif message != "":
        send_message(enc_message)
    try:
        # Now we want to loop over received messages (there might be more than one) and print them
        while True:

            # Receive our "header" containing username length, it's size is defined and constant
            username_header = client_socket.recv(HEADER_LENGTH)

            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(username_header):
                print('Connection closed by the server')
                sys.exit()

            # Convert header to int value
            username_length = int(username_header.decode('utf-8').strip())

            # Receive and decode username
            username = client_socket.recv(username_length).decode('utf-8')

            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())

            if private_chat_username == username and is_private_chat_accepted:
                message = client_socket.recv(message_length)
                if is_check_for_foreign_public_key:
                    encrypter.insert_foreign_public_key(message)
                    is_check_for_foreign_public_key = False
                else:
                    message = encrypter.do_asym_decrypt_of_foreign_message(message)
                    message = message.decode('utf-8')
            else:
                message = client_socket.recv(message_length).decode('utf-8')

            # check private connection authorization
            if private_chat_username == username and is_private_chat_accepted is False:
                if message == "y":
                    is_private_chat_accepted = True
                    is_check_for_foreign_public_key = True
                    send_message(encrypter.get_public_key())
                else:
                    private_chat_username = ""




            # Print message
            print(f'{username} > {message}')

            if f"want to start private chat with {my_username}." in message:
                answer = input(f"Do you want to start private chat with {username}. Input y/n")
                if answer == "y":
                    is_private_chat_accepted = True
                    private_chat_username = username
                    send_message(answer.encode('utf-8'))
                    is_check_for_foreign_public_key = True
                    send_message(encrypter.get_public_key())

    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            sys.exit()

        # We just did not receive anything
        continue

    except Exception as e:
        # Any other exception - something happened, exit
        print('Reading error: '.format(str(e)))
        sys.exit()

