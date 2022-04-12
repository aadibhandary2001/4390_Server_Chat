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

#1. Connect to Server
HOST=socket.gethostbyname(sys.argv[1]) #Get domain name and IP from command line
PORT=int(sys.argv[2]) #Get port from command line

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #Try to create socket nd define as s
    s.connect((HOST, PORT)) #Connect To Port
    exitTok="EXIT" #Set Exit Token
    for line in sys.stdin: #Read line inputs from user indefinitely
        if exitTok == line.rstrip(): #If exitTok, exit for loop
            break
        s.sendall(Authenticator.encrypt(line)) #Encrypt data and send byte stream
        data = Authenticator.decrypt(s.recv(1024)) #Receive back to a buffer of 1024
        print(f"Received {data!r}") #Print Received Result