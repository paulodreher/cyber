#!/usr/bin/python
import urllib.request, urllib.parse, urllib.error ,sys

site = urllib.request.urlopen("https://"+sys.argv[1])
server = site.info()

print("Web server " +server['Server']+ " is up")
