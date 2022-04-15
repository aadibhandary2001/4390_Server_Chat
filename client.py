##############################################################################
#   File:   client.py
#   Author(s): Aadi Bhandary (CE)
#
#   Prodcedures:
#
#
#############################################################################

#File Resources and Imports Below
import socket
import sys
import Encryptor

# Creation of the test Encryptor. All data sent or received passes through this.
Authenticator = Encryptor.Cryptographer(b'test_key', b'test_salt')

# HELLO (Client-ID-A) Protocol Message
def hello(s, line):
    # Get server instructions for login
    s.sendall(Authenticator.encrypt(line))  # Encrypt data and send byte stream
    data = Authenticator.decrypt(s.recv(1024))
    print(f"Received {data!r}")

    # Client can log in
    message = data.split()
    first_word = message[0]
    if first_word == "User_Exists":
        # Begin the RESPONSE procedure.
        # Extracting the random bytes from the message.
        rand = s.recv(1024).decode()
        # For now at least, the secret keys are passwords input by the users.
        password = input()
        # Sending the RES result to compare to the equivalent at the server.
        s.sendall(Authenticator.encrypt(Encryptor.run_SHA1((password + rand).encode())))
        challenge_result = Authenticator.decrypt(s.recv(1024))
        print(f"Received {challenge_result!r}")
        confirmation = challenge_result.split()
        print(confirmation)
        # If the word Successfully is there, it's an AUTH_SUCCESS
        # If not, then the user was notified of login failure.
        if confirmation[0] == "Successfully":
            # Extracting the rand_cookie from the AUTH_SUCCESS
            rand_cookie = confirmation[len(confirmation) - 1]
            # Creation of a key using the existing rand and an alternate Hash.
            key = Encryptor.run_MD5((password + rand).encode())
            # Creation of a cipher using the new key and the rand_cookie.
            cipher = Encryptor.Cryptographer(key, rand_cookie.encode())
            # Running a test of the new cipher.
            s.sendall(cipher.encrypt("Testing. rand_cookie: " + rand_cookie))
            test = cipher.decrypt(s.recv(1024))
            print(f"Test result: {test!r}")

    # Client create new account
    else:
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
    for line in sys.stdin: #Read line inputs from user indefinitely
        if exitTok == line.rstrip(): #If exitTok, exit for loop
            break
        # Client tries to log in
        first_word = line.split()[0]
        if first_word == "HELLO":
            hello(s, line)
        else:
            s.sendall(Authenticator.encrypt(line)) #Encrypt data and send byte stream
            data = Authenticator.decrypt(s.recv(1024)) #Receive back to a buffer of 1024
            print(f"Received {data!r}") #Print Received Result

