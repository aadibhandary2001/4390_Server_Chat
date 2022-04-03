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

#1. Connect to Server
HOST=socket.gethostbyname(sys.argv[1]) #Get domain name and IP from command line
PORT=int(sys.argv[2]) #Get port from command line

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"Hello, world")
    data = s.recv(1024)

print(f"Received {data!r}")