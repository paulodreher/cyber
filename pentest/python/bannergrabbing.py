#!#/usr/bin/python
import socket 
ip = input("ip:" )
port = int(input("port: "))

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((ip,port))
banner = conn.recv(1024)
print(banner)

