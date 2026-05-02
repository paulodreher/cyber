import socket, sys

host = sys.argv[1]

if (len(sys.argv) <= 1):
    print("Use mode: python3 resolver.py <domain>")
else:
    print(host,"--->",socket.gethostbyname(host))
