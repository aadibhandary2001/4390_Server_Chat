##############################################################################
#   File:   client.py
#   Author(s): Aadi Bhandary (CE)
#
#   Prodcedures:
#        response:       -response to the challenge by server for authentication
#        hello:          -initiates client authentication process and server registration
#        connect:        -officially create the TCP connection to the server.
#
#############################################################################

#File Resources and Imports Below
import socket
import sys
import threading

import Encryptor

# Creation of the test Encryptor. All data sent or received passes through this.
# This should be deleted when the UDP Socket is implemented.
Authenticator = Encryptor.Cryptographer(b'test_key', b'test_salt')

global not_exit
not_exit=True

def rcv(conn):
    while not_exit:
        data = Authenticator.decrypt(conn.recv(1024))  # Receive back to a buffer of 1024
        if not data: sys.exit(0)
        print(f"Received {data!r}")  # Print Received Result


# Response to the challenge by server for authentication
def response(s, serv_addr, username, rand):
    # For now at least, the secret keys are passwords input by the users.
    password = input()
    
    # if client enters empty line
    while password == '':
        print("Error: the password can't be empty. \nPlease enter a non empty password:")
        password = input()


    # Sending the RES result to compare to the equivalent at the server.
    response = "RESPONSE " + username + " " + Encryptor.run_SHA1((password + rand).encode())
    RES = Authenticator.encrypt(response)
    s.sendto(RES, serv_addr)
    # Receiving the result of the login attempt
    message, addr = s.recvfrom(1024)
    # Due to Authenticator, this will often post an unwanted "A TCP Connection has ended.
    challenge_result = Authenticator.decrypt(message)
    # If the result has Wrong_Password in it as a string, it failed and will print that fact here.
    # The is not None will be removed when the test Authenticator isn't needed anymore.
    if challenge_result is not None and challenge_result.find('Wrong_Password') >= 0:
        print(f"Received {challenge_result!r}")
        confirmation = challenge_result
        success_flag = False
    # Otherwise, the message must be encrypted, which means authentication went through.
    else:
        confirmation = message
        success_flag = True
    
    return confirmation, password, success_flag


def connect(confirmation, username, password, rand, salt, host_name):
    # Creation of a key using the existing rand and an alternate Hash.
    key = Encryptor.run_MD5((password + rand).encode())
    # Permanent Creation of a cipher using the new key and the salt.
    cipher = Encryptor.Cryptographer(key, salt.encode())
    success_message = cipher.decrypt(confirmation)

    # Extracting the rand_cookie and TCP Port from the AUTH_SUCCESS
    rand_cookie = success_message[len(confirmation) - 2]
    t_port = success_message[len(confirmation) - 1]

    new_sock = socket(socket.AF_INET, socket.SOCK_STREAM)

    new_sock.connect(host_name, t_port)
    # Running a test of the new cipher.
    test_message = "TESTING "
    test_message += username
    test_message += rand_cookie
    new_sock.sendall(cipher.encrypt(test_message))
    test = cipher.decrypt(new_sock.recv(1024))
    print(f"Test result: {test!r}")
    rcvThread = threading.Thread(target=rcv, args=new_sock, daemon=True)
    rcvThread.start()
    return new_sock, cipher


# HELLO (Client-ID-A)
# Initiates client authentication process and server registration
def hello(s, line, serv_addr):
    # Creation of the repeatedly used server address tuple for convenience.
    # Starts authentication process with server
    s.sendto(Authenticator.encrypt(line), serv_addr)
    
    # Recieves server's welcome message + authentication instructions and rand tuple
    data, addr = s.recvfrom(1024)
    result = Authenticator.decrypt(data)
    
    # Deserialize string to tuple
    msg_rand_tuple = tuple(map(str, result.split(', ')))
    
    welcomeMsg = msg_rand_tuple[0]
    if len(msg_rand_tuple) == 3:
        rand = msg_rand_tuple[1]
        salt = msg_rand_tuple[2]
    
    # Print server's welcome message
    print(f"Received {welcomeMsg!r}")
    
    message = welcomeMsg.split()
    first_word = message[0]
    
    # Client is on the list of subscribers
    if first_word == "User_Exists":
        # Respond to server challenge
        confirmation, password, success_flag = response(s, rand)

        # If AUTH_SUCCESS, 
        # else the user was notified of authentication failure
        if success_flag is True:
            # Performing the connection message to end the process of HELLO.
            t_sock, cipher = connect(confirmation, password, rand, salt, serv_addr[0])
            return t_sock, cipher

    # Client creates new account
    else:
        newPassword = input()
        
        # if client enters empty line
        while newPassword == '':
            print("Error: the password can't be empty. \nPlease enter a non empty password:")
            newPassword = input()

        s.sendto(Authenticator.encrypt(newPassword), serv_addr)
        
        data, addr = Authenticator.decrypt(s.recvfrom(1024))
        print(f"Received {data!r}")


#1. Connect to Server
HOST=socket.gethostbyname(sys.argv[1]) #Get domain name and IP from command line
PORT=int(sys.argv[2]) #Get port from command line
# Creation of the server address tuple used for the duration of Authentication/Login.
serv_addr = (HOST, PORT)

exitTok = "EXIT"  # Set Exit Token

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u_sock: #Try to create socket and define as s

    while True:
        line = input()

        # Client tries to log in
        first_word = line.split()[0]
        if first_word == "HELLO":
            # Client enters no clientID
            if len(line.split()) == 1:
                print("Error: ClientID is empty")
                continue

            # If the login was successful, the socket and cipher are returned and usable.
            t_sock, cipher = hello(u_sock, line, serv_addr)
            # Otherwise, this while loop keeps on going.
            if t_sock is not None:
                break
        else:
            print("User must sign in. Please type HELLO (Username)")
    while True:
        line = input()
        if exitTok == line.rstrip():  # If exitTok, exit for loop
            not_exit=False
            break

        # if client enters empty line, continue to next loop iterration
        if line == "\n":
            continue
        t_sock.sendall(Authenticator.encrypt(line))  # Encrypt data and send byte stream
    t_sock.close()
    print("Reached the end!")
    sys.exit("Goodbye!")
