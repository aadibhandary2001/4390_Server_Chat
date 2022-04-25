##############################################################################
#   File:    server.py
#   Author(s): Aadi Bhandary (CE)
#
#   Prodcedures:
#        handleClient:   -reads user requests and messages
#        handleWelcome:  -checks client is on subscriber list and authenticates them,
#                        -or create new client account/subscription
#        challenge:      -challenges client to authenticate itself
#        authSuccess:    -notify client that authentication is successful
#        authFail:       -notify client that authentication has failed
#
#############################################################################
import time # For sleep()

# File Resources and Imports Below
import socket
import sys
import threading

# The code itself works, but it has to have Cryptodome in the same folder as it, and I don't know why.
import Encryptor

# Creation of the test Encryptor. All data sent or received passes through this.
# This should be deleted when the UDP Socket is implemented
Authenticator = Encryptor.Cryptographer(b'test_key', b'test_salt')

# A test dictionary of usernames and passwords. In the final version, these should be stored in a file between uses.
# Wouldn't be hard to export from the file using str.partition(:) or something similar.
# The key is the username and the value is the password.
users = {"dababy": "Apple", "pog": "Banana"}
active_users={}
user_con={}

#CHAT Where two users communicate with each other
def CHAT(conB):
    chat_request="User wishes to chat"
    conB.sendall(Authenticator.encrypt(chat_request))

#CHALLENGE (rand) - challenge the client to authenticate itself
def challenge(newCon, clientID):
    # Asks for password
    greetUser = "User_Exists "
    greetUser += " Username: " + clientID
    greetUser += " Please enter your password: "
    
    # Generation of the rand used for XRES and salt used for the password.
    rand = Encryptor.give_random()
    salt = Encryptor.give_random()

    # The sending of the greeting and rand as a tuple
    # tupple is serialized as a string and must be deserialize by client
    greetUser += ", " + rand
    greetUser += ", " + salt
    newCon.sendall(Authenticator.encrypt(greetUser))
    
    # rand and client's secretKey used in authentication algorithm A3 to output Xres
    Xres = Encryptor.run_SHA1((users[clientID]+rand).encode())
    print("XRES: " + str(Xres))
    
    # Returns Xres, rand, and the salt
    return Xres, rand, salt


# AUTH_SUCCESS(rand_cookie, port_number)
# Notify the client authentication is successful
# Still need to send the new port # for subsequent connection by client?
def authSuccess(newCon, rand, salt, clientID,client_addr):
    # A message to inform the client of the fact they logged in right.
    auth_Success = "AUTH_SUCCESS "
    
    # Creation of the rand_cookie, used as a salt for the new cipher.
    rand_cookie = Encryptor.give_random()
    
    # Creation of a new key for the new cipher
    key = Encryptor.run_MD5((users[clientID] + rand).encode())
    
    # The new cipher, made using the key and rand_cookie.
    # In the final version of this, the cipher should be returned, or something similar.
    cipher = Encryptor.Cryptographer(key, salt.encode())

    # The rand_cookie is sent with the login success message. Again, need to find a way to
    # send data we don't want the user to see in a clean way.
    auth_Success += rand_cookie

    #Set the user ip to the active user pool
    active_users[clientID]=client_addr
    user_con[clientID]=newCon

    print("Address Pair made: ", clientID," at ",active_users.get(clientID))
    print("Socket Pair made: ", clientID," at ",active_users.get(clientID))
    newCon.sendall(cipher.encrypt(auth_Success))

    # Returns variables for possible later use
    # Dunno if I should return rand_cookie or key too
    return cipher


# Notify the client authentication has failed
def authFail(newCon):
    auth_Fail = "Wrong_Password: Please try logging in again with HELLO Client-ID"
    newCon.sendall(Authenticator.encrypt(auth_Fail))


# Receives client's HELLO (Client-ID-A)
# Handles client authentication and new clients
def handleWelcome(newCon, data,client_addr):
    # Client Username
    clientID = data.split()[1]
    
    # User exists on list of subscribers
    if clientID in users:
        # Authenticate client
        Xres, rand, salt = challenge(newCon, clientID)
        
        # Get client RESPONSE
        data = Authenticator.decrypt(newCon.recv(1024))
        print("Says: " + data)
        
        # Correct password-Equivalent to AUTH_SUCCESS
        if str(Xres) == data:
            cipher = authSuccess(newCon, rand, salt, clientID,client_addr)
            
            # Running of a test of the new key.
            test_message = cipher.decrypt(newCon.recv(1024))
            print("Says: ", test_message)

            test_response = test_message[::-1]
            newCon.sendall(cipher.encrypt(test_response))
        
        # Wrong password-Equivalent to AUTH_FAIL
        else:
            authFail(newCon)
    
    # Username doesn't exist
    else:
        # Ask to create password (client's secretKey)
        createPasswordMsg = "User_Not_Found "
        createPasswordMsg += "User " + clientID + " is not on the list of subscribers"
        createPasswordMsg += "Please create a password for the new user: "
        newCon.sendall(Authenticator.encrypt(createPasswordMsg))
        
        # Get client password (client's secretKey)
        data = Authenticator.decrypt(newCon.recv(1024))
        print("Says: ", data)
        
        # Place new user and their password into dictionary users
        users[clientID] = data
        
        # Notify client of successful account creation/subscription
        newUserSuccess = "Successful Account Creation/Subscription for User: " + clientID
        newUserSuccess += "Please try logging into your new account to chat"
        newCon.sendall(Authenticator.encrypt(newUserSuccess))


# Utility Functions
def handleClient(newCon, newAddr):  # Handle client. Threadded function for concurrent client handling
    with newCon:
        print(f"Connected by {newAddr}")  # State status
        while True:  # Recieve bytes until client exits
            data = Authenticator.decrypt(newCon.recv(1024))  # input stream
            if not data:  # if exit, we break
                break
            print(newAddr, "Says: ", data)  # print client input

            # connected client tries to log on by sending "HELLO Client-Username"
            user_command = data.split()[0]
            if user_command == "HELLO":
                handleWelcome(newCon, data, newAddr)
            elif user_command == "CHAT":
                new_message = "Request Sent"
                user_arg = data.split()[1]
                print(user_arg)
                print(user_con.get(user_arg))
                CHAT(user_con.get(user_arg))
                newCon.sendall(Authenticator.encrypt(new_message))  # else, we return values to the client
            else:
                newCon.sendall(Authenticator.encrypt(data))  # else, we return values to the client


# Code Below Sets up welcome socket
HostName = socket.gethostname()  # Obtain Host Name
HOST = socket.gethostbyname(HostName)  # Obtain Host Address
PORT = int(sys.argv[1])  # Obtain port from first argument in command line

print(HostName)  # Print Host Name of Server
print(HOST)  # Print Host Address of Server
print(PORT)  # Print Port in use

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    clients = []
    s.listen()
    while True:
        conn, addr = s.accept()  # accept new clients and create threads for each
        t = threading.Thread(target=handleClient, args=(conn, addr,))  # initialize thread
        t.start()  # start thread
        clients.append(t)  # add thread to thread pool
