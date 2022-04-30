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
import pickle
import os.path

# The code itself works, but it has to have Cryptodome in the same folder as it, and I don't know why.
import Encryptor

# Creation of the test Encryptor. All data sent or received passes through this.
# This should be deleted when the UDP Socket is implemented
# As a reminder to everyone, especially me, Bryce, remember to remove this very soon.
# Authenticator = Encryptor.Cryptographer(b'test_key', b'test_salt')

# A test dictionary of usernames and passwords. In the final version, these should be stored in a file between uses.
# Wouldn't be hard to export from the file using str.partition(:) or something similar.
# The key is the username and the value is the password.
#users = {"dababy": "Apple", "pog": "Banana"}
users = dict()

# Stores a variable as pickle file
def pickleStore(mydata, fileName):
    # Store data
    with open(fileName, 'wb') as handle:
        pickle.dump(mydata, handle, protocol=pickle.HIGHEST_PROTOCOL)


# Loads data from pickle file into a varaible
def pickleLoad(fileName):
    try:
        # load data
        with open(fileName, 'rb') as handle:
            mydata = pickle.load(handle)
        return mydata

     # file doesn't exist
    except FileNotFoundError:
        print("ERROR: could not load data from " + fileName)
        print("\tdata returned/assigned is NoneType")

# Global dictionaries used to handle sorting within the thread.
# The convention is to have the first key then the pair for the name.
active_users= {}
IP_Users = {}
user_ciph = {}
user_con = {}
con_user = {}
user_sess={}

def sendHISTORY(file_name, client_conn,client_ciph):
    print(file_name)
    history_file=open(file_name)
    lines=history_file.readlines()
    for line in lines:
        sendStr=line.strip()
        print(sendStr)
        client_conn.sendall(client_ciph.encrypt(sendStr))

#CHAT history
def HISTORY(clientAID,clientBID,client_conn):
    print("history requested")
    hist_message="history requested"
    clientCiph=user_ciph.get(clientAID)
    client_conn.sendall(clientCiph.encrypt(hist_message))

    fileID=clientAID
    fileID+="-"
    fileID+=clientBID
    fileID+=".txt"
    file_exists=os.path.exists(fileID)
    print(fileID)
    if file_exists:
        print("File does exist")
        sendHISTORY(fileID, client_conn,clientCiph)
    else:
        print("Checking other iteration")
        fileID=clientBID
        fileID+="-"
        fileID+=clientAID
        fileID +=".txt"
        file_exists=os.path.exists(fileID)
        if file_exists:
            print("File does exist")
            sendHISTORY(fileID, client_conn,clientCiph)
        else:
            print("No such history found")


#CHAT Where two users communicate with each other
def CHAT(senderID, conA, conB):
    # Obtaining the receiver's ID.
    receiverID = con_user.get(conB)

    # Store Chat History
    histFileName = senderID
    histFileName+="-"
    histFileName+=receiverID
    histFileName += ".txt"
    histFile = open(histFileName, "a")

    # Getting the needed ciphers based on the client IDs
    userA_ciph = user_ciph.get(senderID)
    userB_ciph = user_ciph.get(receiverID)
    user_sess[senderID] = True

    # Creation and sending of appropriate messages to both clients.
    chat_request = "CHATREQUEST "
    chat_request += senderID
    chat_request += " wishes to chat"
    conB.sendall(userB_ciph.encrypt(chat_request))
    req_sent = "Request Sent, wait for their response"
    conA.sendall(userA_ciph.encrypt(req_sent))  # else, we return values to the client

    userB_msg=userB_ciph.decrypt(conB.recv(1024))
    while True:
        end_msg = "CHATENDED"
        if userB_msg == "END":
            print(receiverID," has ended chat")
            conA.sendall(userA_ciph.encrypt(end_msg))
            conB.sendall(userB_ciph.encrypt(end_msg))
            user_sess[senderID]=False
            user_sess[receiverID]=False
            break;
        else:
            receiverstr = receiverID
            receiverstr += " says: "
            receiverstr += userB_msg
            receiverstr+="\n"
            print(receiverstr)
            histFile.write(receiverstr)
            conA.sendall(userA_ciph.encrypt(userB_msg))

        userA_msg=userA_ciph.decrypt(conA.recv(1024))
        if userA_msg == "END":
            print(senderID, " has ended chat")
            conB.sendall(userB_ciph.encrypt(end_msg))
            conA.sendall(userA_ciph.encrypt(end_msg))
            user_sess[senderID] = False
            user_sess[receiverID] = False
            break;
        else:
            senderstr = senderID
            senderstr += " says: "
            senderstr += userA_msg
            print(senderstr)
            senderstr += "\n"
            histFile.write(senderstr)
            conB.sendall(userB_ciph.encrypt(userA_msg))
        userB_msg = userB_ciph.decrypt(conB.recv(1024))
        print(receiverID, "says: ", userB_msg)
    histFile.write("\n")
    histFile.close()

def handle_auth(HOST, PORT, t_port):

    # Creation of a dictionary to store in-progress logins, rather than risking getting blocked.
    login_pending = dict()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as auth_sock:
        # Binding the UDP Socket to the port number that was entered
        auth_sock.bind((HOST, PORT))
        while True:
            message, cli_address = auth_sock.recvfrom(1024)
            str_message = message.decode()
            print(cli_address, "Says", str_message)
            request = str_message.split()
            # Extracting the type of client request.
            request_type = request[0]
            # Extracting the client's username from their request
            client_ID = request[1]

            if request_type == "HELLO":
                # If a user is trying to login from multiple places at once, it soon won't be allowed.
                # May want to add another check for this with active users.
                if client_ID in login_pending:
                    login_exception(auth_sock, cli_address)
                elif client_ID not in users:
                    make_user(auth_sock, request, cli_address)
                else:
                    # Extracting the portions of the message used for the Auth_Success/failure
                    ID, XRES, rand, salt= challenge(auth_sock, cli_address, request)
                    login_pending[ID] = (XRES, rand, salt)
            elif request_type == "RESPONSE":
                # Extracting the client's info to pass to AuthCheck
                cli_info = login_pending.get(client_ID)
                # Calling AuthCheck to see if the client successfully logged in.
                AuthCheck(auth_sock, client_ID, cli_info, request, cli_address, t_port)
                # Whether it succeeded or failed, the client's info will be removed from the pending logins.
                del login_pending[client_ID]
            else:
                error_message = "Unknown UDP request type received."
                auth_sock.sendto(error_message.encode(), cli_address)


# A method to handle the situation whee a user tries to login from multiple clients at once— this is not allowed
def login_exception(auth_sock, cli_addr):
    multiple_log_message = "LOGIN_INVALID: Simultaneous login attempt detected. Please login as a valid user"
    auth_sock.sendto(multiple_log_message.encode(), cli_addr)


# CHALLENGE (rand) - challenge the client to authenticate itself
def challenge(auth_sock, dest_addr, clientInfo):
    # Asks for password
    clientID = clientInfo[1]
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
    auth_sock.sendto(greetUser.encode(), dest_addr)
    
    # rand and client's secretKey used in authentication algorithm A3 to output Xres
    Xres = Encryptor.run_SHA1((users[clientID]+rand).encode())
    print("XRES: " + str(Xres))
    
    # Returns Xres, rand, and the salt
    return clientID, str(Xres), rand, salt


# AuthCheck, a method to cleanly see if a user is authenticated, and to call the proper message if they were.
def AuthCheck(auth_sock, cli_ID , cli_info, response, cli_addr,t_port):
    # If XRES matches RES, run AuthSuccess
    if cli_info[0] == response[2]:
        authSuccess(auth_sock, cli_info, cli_ID, cli_addr, t_port)
    # Otherwise, run Auth_Fail
    else:
        authFail(auth_sock, cli_addr)


# AUTH_SUCCESS(rand_cookie, port_number)
# Notify the client authentication is successful
# Still need to send the new port # for subsequent connection by client?
def authSuccess(auth_sock, cli_info, clientID, cli_addr, serv_port):
    # Extracting rand and the salt for use.
    rand = cli_info[1]
    salt = cli_info[2]

    # A message to inform the client of the fact they logged in right.
    auth_Success = "AUTH_SUCCESS "
    
    # Creation of the rand_cookie, used as a salt for the new cipher.
    rand_cookie = Encryptor.give_random()
    
    # Creation of a new key for the new cipher
    key = Encryptor.run_MD5((users[clientID] + rand).encode())
    
    # The new cipher, made using the key and the salt.
    # In the final version of this, the cipher should be returned, or something similar.
    cipher = Encryptor.Cryptographer(key, salt.encode())

    # The rand_cookie and port are sent with the login success message. Again, need to find a way to
    # send data we don't want the user to see in a clean way.
    auth_Success += rand_cookie
    auth_Success += (" "+ str(serv_port))

    # Set the user ip to the active user pool
    user_ciph[clientID] = cipher
    IP_Users[cli_addr[0]]=clientID

    auth_sock.sendto(cipher.encrypt(auth_Success), cli_addr)



# Notify the client authentication has failed
def authFail(auth_sock, cli_addr):
    auth_Fail = "Wrong_Password: Please try logging in again with HELLO Client-ID"
    auth_sock.sendto(auth_Fail.encode(), cli_addr)


# Handle welcome may have to be broken into chunks in order to handle multiple clients.

# Receives client's HELLO (Client-ID-A)
# Handles client authentication and new clients
def make_user(auth_sock, data, client_addr):
    # Client Username
    clientID = data[1]

    # Ask to create password (client's secretKey)
    createPasswordMsg = "User_Not_Found "
    createPasswordMsg += "User " + clientID + " is not on the list of subscribers"
    createPasswordMsg += " Please create a password for the new user: "
    print(createPasswordMsg)
    auth_sock.sendto(createPasswordMsg.encode(), client_addr)
        
    # Get client password (client's secretKey)
    newData, cli_addr = auth_sock.recvfrom(1024)
    newPass = newData.decode()
    print(cli_addr, " Says: ", newPass)

    # Place new user and their password into dictionary users
    users[clientID] = newPass

    # Stores users dictionary as pickle file
    pickleStore(users, 'users.pickle')
        
    # Notify client of successful account creation/subscription
    newUserSuccess = "Successful Account Creation/Subscription for User: " + clientID
    newUserSuccess += "Please try logging into your new account to chat"
    auth_sock.sendto(newUserSuccess.encode(), client_addr)


# Utility Functions
def handleClient(newCon, newAddr):  # Handle client. Threadded function for concurrent client handling
    with newCon:
        # Receiving the test message that every client will send first.
        clientID = IP_Users.get(newAddr[0])

        active_users[clientID] = newAddr
        user_con[clientID] = newCon
        con_user[newCon] = clientID
        global user_sess
        user_sess[clientID]=False

        active_cipher = user_ciph.get(clientID)

        print("Address Pair made: ", clientID, " at ", active_users.get(clientID))
        print("Socket Pair made: ", clientID, " at ", active_users.get(clientID))
        print(f"Connected by {newAddr}")  # State status

        test_message = active_cipher.decrypt(newCon.recv(1024))
        print(newAddr, "Says: ", test_message)
        test_response = "Test Successful"
        newCon.sendall(active_cipher.encrypt(test_response))

        while True:  # Recieve bytes until client exits
            if not user_sess.get(clientID): #if the user is not in an active chat session.
                print(user_sess.get(clientID))
                data = active_cipher.decrypt(newCon.recv(1024))  # input stream
                print(newAddr, clientID, " Says: ", data)  # print client input

                if not data:  # if exit, we break
                    print(newAddr, clientID, "has logged off")
                    break

            # connected client tries to log on by sending "HELLO Client-Username"
                user_command = data.split()[0]

                if user_command == "CHAT":
                    user_arg = data.split()[1]
                    CHAT(con_user.get(newCon), newCon, user_con.get(user_arg))
                elif user_command == "CHATACCEPT":
                    user_sess[clientID]=True
                    print(user_sess.get(clientID))
                elif user_command == "HISTORY_REQ":
                    user_arg = data.split()[1]
                    HISTORY(clientID,user_arg,newCon)
                else:
                    newCon.sendall(active_cipher.encrypt(data))  # else, we return values to the client


# Code Below Sets up welcome socket
HostName = socket.gethostname()  # Obtain Host Name
HOST = socket.gethostbyname(HostName)  # Obtain Host Address
PORT = int(sys.argv[1])  # Obtain port from first argument in command line

print(HostName)  # Print Host Name of Server
print(HOST)  # Print Host Address of Server
print(PORT)  # Print Port in use

# Loads data from pickle file into users dictionary
users = pickleLoad('users.pickle')
if users is None: # if pickleLoad returns NoneType (file not exists)
    users = dict()
print(users)

# Creation of a TCP Welcoming Socket with a randomized port number.
# Because the first part of welcoming is done by UDP and it sends the port number, this is suitable.

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t_sock:
    # Binding the TCP socket to a random port number based on what is available, then saving said port number for use.
    t_sock.bind(('', 0))
    welcome_port = t_sock.getsockname()[1]

    threads = []
    # Creation of a UDP Socket with the specified port number, used to do authentication
    # This has its own thread since it must run parallel to all other threads.

    u_thread = threading.Thread(target=handle_auth, args = (HOST, PORT, welcome_port))
    u_thread.start()
    threads.append(u_thread)
    t_sock.listen()
    while True:
        conn, addr = t_sock.accept()  # accept new clients and create threads for each
        t = threading.Thread(target=handleClient, args=(conn, addr))  # initialize thread
        t.start()  # start thread
        threads.append(t)  # add thread to thread pool


