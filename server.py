##############################################################################
#   File:   main.py
#   Author(s): Aadi Bhandary (CE)
#
#   Prodcedures:
#       handleWelcome:  -reads from socket and checks subscriber list
#       handleClient:   -reads user requests and messages
#       messageSender:  -operates the message send queue. sends to ledger and
#
#############################################################################

# File Resources and Imports Below
import socket
import sys
import threading

# The code itself works, but it has to have Cryptodome in the same folder as it, and I don't know why.
import Encryptor

# Creation of the test Encryptor. All data sent or received passes through this.
Authenticator = Encryptor.Cryptographer(b'test_key', b'test_salt')

# A test dictionary of usernames and passwords. In the final version, these should be stored in a file between uses.
# Wouldn't be hard to export from the file using str.partition(:) or something similar.
# The key is the username and the value is the password.
users = {"dababy": "Apple", "pog": "Banana"}


# usernames = ["dababy", "pog"]
# passwords = ["Apple", "Banana"]

# HELLO (Client-ID-A) Protocal Message
def hello(newCon, data):
    # Client Username
    clientID = data.split()[1]

    # Username exists -Changed from usernames to users
    if clientID in users:
        # Asks for password- Equivalent to CHALLENGE
        greetUser = "User_Exists "
        greetUser += " Username: " + clientID
        greetUser += " Please enter your password: "
        # Generation of the rand used for XRES
        rand = Encryptor.give_random()
        # The sending of the greeting and rand are currently separate for readability.
        # Changing it to a tuple or something would help.
        newCon.sendall(Authenticator.encrypt(greetUser))
        newCon.sendall(rand.encode())

        Xres = Encryptor.run_SHA1((users[clientID]+rand).encode())
        print("XRES: " + str(Xres))
        # Get client RESPONSE
        data = Authenticator.decrypt(newCon.recv(1024))
        print("Says: "+ data)
        # index = usernames.index(clientID)

        # Correct password-Equivalent to AUTH_SUCCESS
        if str(Xres) == data:
            # A message to inform the client of the fact they logged in right.
            loginSuccess = "Successfully Logged in "
            # Creation of the rand_cookie, used as a salt for the new cipher.
            rand_cookie = Encryptor.give_random()
            # The rand_cookie is sent with the login success message. Again, need to find a way to
            # send data we don't want the user to see in a clean way.
            loginSuccess += rand_cookie
            newCon.sendall(Authenticator.encrypt(loginSuccess))
            # Creation of a new key for the new cipher
            key = Encryptor.run_MD5((users[clientID] + rand).encode())
            # The new cipher, made using the key and rand_cookie.
            # In the final version of this, the cipher should be returned, or something similar.
            cipher = Encryptor.Cryptographer(key, rand_cookie.encode())
            # Running of a test of the new key.
            test_message = cipher.decrypt(newCon.recv(1024))
            print("Says: ", test_message)
            test_response = test_message[::-1]
            newCon.sendall(cipher.encrypt(test_response))

        # Wrong password-Equivalent to AUTH_FAIL
        else:
            loginFailure = "Wrong_Password: Please try logging in again"
            newCon.sendall(Authenticator.encrypt(loginFailure))

    # Username doesn't exist
    else:
        # Adds clientID to usernames list
        # usernames.append(clientID)

        # Asks to create password
        createPasswordMsg = "User_Not_Found"
        createPasswordMsg += "User '" + clientID + "' is not on the list of subscribers"
        createPasswordMsg += "Please create a password for the new user: "
        newCon.sendall(Authenticator.encrypt(createPasswordMsg))

        # place new user password into list
        data = Authenticator.decrypt(newCon.recv(1024))
        print("Says: ", data)
        # index = usernames.index(clientID)
        # passwords.append(data)
        users[clientID] = data
        newUserSucess = "Sucessfully Created Account for User: " + clientID
        newUserSucess += "Please try logging into your new account to chat"
        newCon.sendall(Authenticator.encrypt(newUserSucess))


# Utility Functions
def handleClient(newCon, newAddr):  # Handle client. Threadded function for concurrent client handling
    with newCon:
        print(f"Connected by {newAddr}")  # State status
        while True:  # Recieve bytes until client exits
            data = Authenticator.decrypt(newCon.recv(1024))  # input stream
            if not data:  # if exit, we break
                break
            print(newAddr, "Says: ", data)  # print client input
            newData = data[::-1]  # reverse client input

            # connected client tries to log on by sending "HELLO Client-Username"
            first_word = data.split()[0]
            if first_word == "HELLO":
                hello(newCon, data)
            else:
                newCon.sendall(Authenticator.encrypt(newData))  # else, we return values to the client


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

# 3. Set up message queues
# 4. Start Threads
