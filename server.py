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

#File Resources and Imports Below
import socket
import sys

#1. Set up welcome socket
HostName=socket.gethostname() #Obtain Host Name
HOST=socket.gethostbyname(HostName) #Obtain Host Address
PORT=int(sys.argv[1]) #Obtain port from first argument in command line

print(HostName)
print(HOST)
print(PORT)

with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr= s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data=conn.recv(1024)
            newData=data[::-1]
            if not data:
                break
            conn.sendall(newData)

#2. Set up TCP Socket
#3. Set up message queues
#4. Start Threads