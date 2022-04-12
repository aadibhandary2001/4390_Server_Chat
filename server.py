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
import threading

# The code itself works, but it has to have Cryptodome in the same folder as it, and I don't know why.
import Encryptor

Authenticator = Encryptor.Cryptographer(b'test_key', b'test_salt')

#Utility Functions
def handleClient(newCon,newAddr): #Handle client. Threadded function for concurrent client handling
    with newCon:
        print(f"Connected by {newAddr}") #State status
        while True: #Recieve bytes until client exits
            data=Authenticator.decrypt(newCon.recv(1024)) #input stream
            if not data: #if exit, we break
                break
            print(newAddr,"Says: ",data) #print client input
            newData=data[::-1]  #reverse client input
            newCon.sendall(Authenticator.encrypt(newData))#else, we return values to the client

#Code Below Sets up welcome socket
HostName=socket.gethostname() #Obtain Host Name
HOST=socket.gethostbyname(HostName) #Obtain Host Address
PORT=int(sys.argv[1]) #Obtain port from first argument in command line

print(HostName) #Print Host Name of Server
print(HOST) #Print Host Address of Server
print(PORT) #Print Port in use

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    clients=[]
    s.listen()
    while True:
            conn, addr= s.accept() #accept new clients and create threads for each
            t=threading.Thread(target=handleClient,args=(conn,addr,)) #initialize thread
            t.start() #start thread
            clients.append(t) #add thread to thread pool

#3. Set up message queues
#4. Start Threads