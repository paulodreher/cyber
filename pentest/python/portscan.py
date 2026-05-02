#!/usr/bin/python
import socket,sys

for port in range(1,65535):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if conn.connect_ex((sys.argv[1],port)) == 0:
        print ("[OPEN]",port)
        conn.close()
