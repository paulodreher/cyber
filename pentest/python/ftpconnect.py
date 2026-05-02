#!/usr/bin/python
import socket,sys

ip = input("ip:")
print ("Connecting to server")
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((ip,21))
print(conn.recv(1024))
    
print ("Sending username")
conn.send(str.encode("USER ricardo\r\n"))
print(conn.recv(1024))

print ("Sending password")
conn.send(str.encode("PASS ricardo\r\n"))
print(conn.recv(1024))
