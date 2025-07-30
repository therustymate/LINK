from socket import *
import sys

while True:
    with socket(AF_INET, SOCK_STREAM) as s:
        s.bind(("localhost", 8080))
        while True:
            s.listen()
            conn, addr = s.accept()
            while True:
                data = conn.recv(1024)
                if data:
                    print(data)
                    if data == b"/exit":
                        break

sys.exit(1)