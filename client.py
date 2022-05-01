##############################################################################
#   File:   client.py
#   Author(s): Aadi Bhandary (CE), Bryce McFarlane(CE)
#
#   Prodcedures:
#        response:       -response to the challenge by server for authentication
#        hello:          -initiates client authentication process and server registration
#        connect:        -officially create the TCP connection to the server.
#
#############################################################################

#File Resources and Imports Below
import os
import socket
import sys
import threading
import time
import Encryptor

#globals for chat
not_exit=True
accept_sent=False
msgsent=False

# Initiation of the TCP port and cipher
TCP_Sock = None
user_cipher = None

#function to operate timeout
def timeoutFunc():
    starttime=time.time()
    currtime=time.time()
    global msgsent
    while (currtime-starttime)<180:
        if msgsent:
            starttime=time.time()
            msgsent=False
        if accept_sent:
            starttime = time.time()
        currtime=time.time()
    print("Away for too long. Goodbye")
    os._exit(os.EX_OK)

#function to operate receive thread
def rcv(conn,ciph):
    chat_accepted="CHATACCEPT"
    global accept_sent

    while not_exit:
        data = ciph.decrypt(conn.recv(1024))  # Receive back to a buffer of 1024

        if not data:
            sys.exit(0)

        data_splt = data.split()
        if data_splt[0] == "CHATREQUEST":
            if not accept_sent:
                conn.sendall(ciph.encrypt(chat_accepted))
                accept_sent=True
                print(accept_sent)
            print("Chat Session Initiated")
        if data_splt[0] == "CHATENDED":
            accept_sent = False
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
    # RES has its spaces removed to prevent spaces from messing with the splitting.
    RES = str(Encryptor.run_SHA1((password + rand).encode())).replace(" ", "")
    response = "RESPONSE " + username + " " + RES
    s.sendto(response.encode(), serv_addr)
    # Receiving the result of the login attempt
    message, addr = s.recvfrom(1024)
    # Making a string version of the message and taking the byte symbol out.
    # Cannot use decode because if the authentication succeeded, it will contain invalid utf bytes.
    challenge_result = str(message).replace("b'", "")
    # If the result has Wrong_Password in it as a string, it failed and will print that fact here.
    # The is not None will be removed when the test Authenticator isn't needed anymore.
    if challenge_result.find('Wrong_Password') >= 0:
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
    login_data = success_message.split()

    rand_cookie = login_data[len(login_data) - 2]
    t_port = int(login_data[len(login_data) - 1])
    # Making and connecting the new TCP socket
    new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    new_sock.connect((host_name, t_port))

    # Running a test of the new cipher.
    test_message = "TESTING "
    test_message += username
    test_message += (" " + rand_cookie)
    new_sock.sendall(cipher.encrypt(test_message))
    test = cipher.decrypt(new_sock.recv(1024))
    print(f"Test result: {test!r}")
    global TCP_Sock
    global user_cipher
    TCP_Sock = new_sock
    user_cipher = cipher
    rcvThread = threading.Thread(target=rcv, args=(new_sock,cipher), daemon=True)
    rcvThread.start()


# HELLO (Client-ID-A)
# Initiates client authentication process and server registration
def hello(s, line, serv_addr):
    # Creation of the repeatedly used client_ID for convenience
    # Starts authentication process with server
    client_ID = line.split()[1]

    s.sendto(line.encode(), serv_addr)

    # A flag to say if login was successful.
    success_flag = False

    # Recieves server's welcome message + authentication instructions and rand tuple
    data, addr = s.recvfrom(1024)
    result = data.decode()
    # If login was invalid due to simultaneous login attempts, it prints that fact.
    if result.find("LOGIN_INVALID") >= 0:
        print(result)
        return success_flag

    # Deserialize string to tuple
    msg_rand_tuple = tuple(map(str, result.split(', ')))
    
    welcomeMsg = msg_rand_tuple[0]
    # If the user exists, rand and salt are extracted for later use.
    if len(msg_rand_tuple) == 3:
        rand = msg_rand_tuple[1]
        salt = msg_rand_tuple[2]
    
    # Print server's welcome message
    print(f"Received {welcomeMsg!r}")
    
    message = welcomeMsg.split()
    server_command = message[0]
    
    # Client is on the list of subscribers
    if server_command == "User_Exists":
        # Respond to server challenge
        confirmation, password, success_flag = response(s, serv_addr, client_ID, rand)

        # If AUTH_SUCCESS, 
        # else the user was notified of authentication failure
        if success_flag is True:
            # Performing the connection message to end the process of HELLO.
            connect(confirmation, client_ID , password, rand, salt, serv_addr[0])

    # Client creates new account
    else:
        # Waiting for the client to create a new password.
        newPassword = input()
        
        # if client enters empty line
        while newPassword == '':
            print("Error: the password can't be empty. \nPlease enter a non empty password:")
            newPassword = input()
        # Sending the message of the new password to the server.
        # Ideally this would be done with Asymmetric Encryption, but that is not implemented in this build.
        passMessage = "NEW_PASS "+ client_ID+ " "+newPassword
        s.sendto(passMessage.encode(), serv_addr)

        # Receiving the server's response to the new password
        pass_data, addr = s.recvfrom(1024)
        pass_result = pass_data.decode()
        print(f"Received {pass_result!r}")
    # Returning the success flag to say if the for-loop below can break.
    return success_flag


#1. Connect to Server
HOST=socket.gethostbyname(sys.argv[1]) #Get domain name and IP from command line
PORT=int(sys.argv[2]) #Get port from command line
# Creation of the server address tuple used for the duration of Authentication/Login.
serv_addr = (HOST, PORT)

exitTok = "EXIT"  # Set Exit Token
timeoutThread=threading.Thread(target=timeoutFunc,args=(), daemon=True)
timeoutThread.start()

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

            # If the login was successful, login_success will be true.
            login_success = hello(u_sock, line, serv_addr)
            # Otherwise, this while loop keeps on going.
            if login_success is True:
                break
        else:
            print("User must sign in. Please type HELLO (Username)")

while True:
    line = input()
    if exitTok == line.rstrip():  # If exitTok, exit for loop
        not_exit = False
        break

    # if client enters empty line, continue to next loop iterration
    if line == "\n":
        continue
    msgsent=True
    TCP_Sock.sendall(user_cipher.encrypt(line))  # Encrypt data and send byte stream
TCP_Sock.close()
print("Reached the end!")
sys.exit("Goodbye!")
