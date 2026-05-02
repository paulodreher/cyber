#!/usr/bin/python
import requests,sys

site = requests.get("https://www."+sys.argv[1])
status = site.status_code
if (len(sys.argv)<=1):
    print("Use mode: python3 webscrapping <site>")
elif (status == 200):
    print("Page found")
else:
    print("Page not found")
    
