##############################################################################
#   File:   client.py
#   Author(s): Aadi Bhandary (CE)
#
#   Prodcedures:
#        response:       -response to the challenge by server for authentication
#        hello:          -initiates client authentication process and server registration
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
def response(s, rand, salt):
    # For now at least, the secret keys are passwords input by the users.
    password = input()
    
    # if client enters empty line
    while password == '':
        print("Error: the password can't be empty. \nPlease enter a non empty password:")
        password = input()


    # Sending the RES result to compare to the equivalent at the server.
    RES = Authenticator.encrypt(Encryptor.run_SHA1((password + rand).encode()))
    s.sendall(RES)
    # Receiving the result of the login attempt
    message = s.recv(1024)
    # Due to Authenticator, this will often post an unwanted "A TCP Connection has ended.
    challenge_result = Authenticator.decrypt(message)
    # If the result has Wrong_Password in it as a string, it failed and will print that fact here.
    # The is not None will be removed when the test Authenticator isn't needed anymore.
    if challenge_result is not None and challenge_result.find('Wrong_Password') >= 0:
        print(f"Received {challenge_result!r}")
        confirmation = challenge_result
    # Otherwise, it will create a temporary version of the cipher to decrypt the message properly and give confirmation.
    else:
        # Temporarily creating the new cipher through the key and the salt to obtain the Auth_Success
        key = Encryptor.run_MD5((password + rand).encode())
        cipher = Encryptor.Cryptographer(key, salt.encode())
        # Creating and printing the confirmation.
        confirmation = cipher.decrypt(message).split()
        print(confirmation)
    
    return confirmation, password


# HELLO (Client-ID-A)
# Initiates client authentication process and server registration
def hello(s, line):
    # Starts authentication process with server
    s.sendall(Authenticator.encrypt(line))
    
    # Recieves server's welcome message + authentication instructions and rand tuple
    data = Authenticator.decrypt(s.recv(1024))
    
    # Deserialize string to tuple
    msg_rand_tuple = tuple(map(str, data.split(', ')))
    
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
        confirmation, password = response(s, rand, salt)
    
        # If AUTH_SUCCESS, 
        # else the user was notified of authentication failure
        if confirmation[0] == "AUTH_SUCCESS":
            # Extracting the rand_cookie from the AUTH_SUCCESS
            rand_cookie = confirmation[len(confirmation) - 1]
            
            # Creation of a key using the existing rand and an alternate Hash.
            key = Encryptor.run_MD5((password + rand).encode())
            
            # Permanent Creation of a cipher using the new key and the rand_cookie.
            cipher = Encryptor.Cryptographer(key, salt.encode())
            
            # Running a test of the new cipher.
            s.sendall(cipher.encrypt("Testing. rand_cookie: " + rand_cookie))
            test = cipher.decrypt(s.recv(1024))
            print(f"Test result: {test!r}")
            rcvThread = threading.Thread(target=(rcv), args=(s,),daemon=True)
            rcvThread.start()
    # Client creates new account
    else:
        newPassword = input()
        
        # if client enters empty line
        while newPassword == '':
            print("Error: the password can't be empty. \nPlease enter a non empty password:")
            newPassword = input()

        s.sendall(Authenticator.encrypt(newPassword))
        
        data = Authenticator.decrypt(s.recv(1024))
        print(f"Received {data!r}")


#1. Connect to Server
HOST=socket.gethostbyname(sys.argv[1]) #Get domain name and IP from command line
PORT=int(sys.argv[2]) #Get port from command line


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #Try to create socket nd define as s
    s.connect((HOST, PORT)) #Connect To Port
    exitTok="EXIT" #Set Exit Token

    while True:
        line=input()

        # Client tries to log in
        first_word = line.split()[0]
        if first_word == "HELLO":
            # Client enters no clientID
            if len(line.split()) == 1:
                print("Error: ClientID is empty")
                continue
            
            hello(s, line)
            break;
        else:
            print("User must sign in. Please type HELLO (Username)")
    while True:
        line=input()
        if exitTok == line.rstrip():  # If exitTok, exit for loop
            not_exit=False
            break

        # if client enters empty line, continue to next loop iterration
        if line == "\n":
            continue
        s.sendall(Authenticator.encrypt(line))  # Encrypt data and send byte stream
    print("Reached the end!")
    sys.exit("Goodbye!")