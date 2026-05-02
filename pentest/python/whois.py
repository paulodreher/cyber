#!/usr/bin/python
import codecs,socket,sys

server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.connect(("whois.iana.org",43))
server.send(str.encode(sys.argv[1]+"\r\n"))
reply = server.recv(1024).split()
server.close()

whois = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
whois.connect((reply[19].decode(),43))
whois.send(str.encode(sys.argv[1]+"\r\n"))
print(codecs.decode(whois.recv(1024),'ISO-8859-1'))
whois.close()
