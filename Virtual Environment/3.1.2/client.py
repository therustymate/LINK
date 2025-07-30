from socket import *
import sys

while True:
    with socket(AF_INET, SOCK_STREAM) as s:
        s.connect(("localhost", 1234))
        while True:
            s.send(input().encode())


sys.exit(0)