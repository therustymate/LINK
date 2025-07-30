from socket import *
from threading import Thread

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import os

import hashlib
import hmac

import logging
import time
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s\t%(levelname)s\t%(message)s",
    filename="{}.LINK.log".format(time.strftime("%Y-%m-%d"))
)

class LINK:
    class Server:
        def __init__(self, INPUT: tuple, OUTPUT: tuple):
            self.INPUT = INPUT
            self.OUTPUT = OUTPUT

            self.RSA_KEY = RSA.generate(2048)
            self.RSA_PUBLIC = self.RSA_KEY.publickey().export_key()
            self.RSA_HASH = hashlib.sha512(self.RSA_PUBLIC).digest()

            self.VERIFY_KEY = os.urandom(16)

            self.IN_OBJ = socket(AF_INET, SOCK_STREAM)
            self.IN_OBJ.bind(self.INPUT)
            self.IN_OBJ.listen()
            self.IN = self.IN_OBJ.accept()[0]
            self.IN.sendall(self.RSA_HASH)
            self.IN.sendall(self.RSA_PUBLIC)

            AES_LOCKED = self.IN.recv(1024)
            RSA_OBJ = PKCS1_OAEP.new(self.RSA_KEY)
            AES_KEY = RSA_OBJ.decrypt(AES_LOCKED)
            self.LOCKER = AES.new(AES_KEY, AES.MODE_ECB)
            logging.info("SERVER: IN Bind {}:{}".format(self.INPUT[0], self.INPUT[1]))

            KEY_TRANSFER = pad(self.VERIFY_KEY, AES.block_size)
            KEY_TRANSFER = self.LOCKER.encrypt(KEY_TRANSFER)
            self.IN.send(KEY_TRANSFER)

            self.OUT = socket(AF_INET, SOCK_STREAM)
            self.OUT.connect(self.OUTPUT)
            logging.info("SERVER: OUT Bind {}:{}".format(self.OUTPUT[0], self.OUTPUT[1]))

            self.IN_thread = Thread(target=self.start_IN)
            self.IN_thread.start()

            self.OUT_thread = Thread(target=self.start_OUT)
            self.OUT_thread.start()

            logging.info("SERVER: STARTED")

        def start_IN(self):
            try:
                while True:
                    try:
                        VERIFY = self.IN.recv(1048576)
                        DATA = self.IN.recv(1048576)
                        if DATA:
                            if VERIFY == hmac.new(self.VERIFY_KEY, DATA, hashlib.sha256).hexdigest().encode():
                                logging.info("SERVER: Data verified [{}]".format(VERIFY.decode()[8:]))
                                DATA = self.LOCKER.decrypt(DATA)
                                DATA = unpad(DATA, AES.block_size)
                                self.OUT.send(DATA)
                                logging.info("SERVER: OUT Data transfer")
                            else:
                                logging.critical("SERVER: Verification failed")
                    except Exception as e:
                        logging.error(f"SERVER: {e}")
                        self.IN.close()
                        self.OUT.close()
                        sys.exit(1)
            except Exception as e:
                logging.critical(f"SERVER: {e}")
                sys.exit(1)
        def start_OUT(self):
            try:
                while True:
                    try:
                        DATA = self.OUT.recv(1048576)
                        if DATA:
                            DATA = pad(DATA, AES.block_size)
                            DATA = self.LOCKER.encrypt(DATA)
                            VERIFY = hmac.new(self.VERIFY_KEY, DATA, hashlib.sha256).hexdigest().encode()
                            self.IN.send(VERIFY)
                            self.IN.send(DATA)
                            logging.info("SERVER: IN Data transfer")
                    except Exception as e:
                        logging.error(f"SERVER: {e}")
                        self.IN.close()
                        self.OUT.close()
                        sys.exit(1)
            except Exception as e:
                logging.critical(f"SERVER: {e}")
                sys.exit(1)

    class Client:
        def __init__(self, INPUT: tuple, OUTPUT: tuple):
            self.INPUT = INPUT
            self.OUTPUT = OUTPUT

            self.IN = socket(AF_INET, SOCK_STREAM)
            self.IN.connect(self.INPUT)

            PUBLIC_KEY_HASH = self.IN.recv(1024)
            PUBLIC_KEY = self.IN.recv(2048)
            if hashlib.sha512(PUBLIC_KEY).digest() != PUBLIC_KEY_HASH:
                logging.critical("CLIENT: Invalid server key")
                sys.exit(1)

            self.aes_key = get_random_bytes(16)
            RSA_OBJ = PKCS1_OAEP.new(RSA.import_key(PUBLIC_KEY))
            AES_LOCKED = RSA_OBJ.encrypt(self.aes_key)
            self.IN.sendall(AES_LOCKED)
            self.LOCKER = AES.new(self.aes_key, AES.MODE_ECB)
            logging.info("CLIENT: IN Bind {}:{}".format(self.INPUT[0], self.INPUT[1]))

            KEY_TRANSFER = self.IN.recv(1024)
            KEY_TRANSFER = self.LOCKER.decrypt(KEY_TRANSFER)
            KEY_TRANSFER = unpad(KEY_TRANSFER, AES.block_size)
            self.VERIFY_KEY = KEY_TRANSFER

            self.OUT_OBJ = socket(AF_INET, SOCK_STREAM)
            self.OUT_OBJ.bind(self.OUTPUT)
            self.OUT_OBJ.listen()
            self.OUT = self.OUT_OBJ.accept()[0]
            logging.info("CLIENT: OUT Bind {}:{}".format(self.OUTPUT[0], self.OUTPUT[1]))

            self.IN_thread = Thread(target=self.start_IN)
            self.IN_thread.start()

            self.OUT_thread = Thread(target=self.start_OUT)
            self.OUT_thread.start()

            logging.info("CLIENT: STARTED")

        def start_IN(self):
            try:
                while True:
                    try:
                        VERIFY = self.IN.recv(1048576)
                        DATA = self.IN.recv(1048576)
                        if DATA:
                            if VERIFY == hmac.new(self.VERIFY_KEY, DATA, hashlib.sha256).hexdigest().encode():
                                logging.info("CLIENT: Data verified [{}]".format(VERIFY.decode()[8:]))
                                DATA = self.LOCKER.decrypt(DATA)
                                DATA = unpad(DATA, AES.block_size)
                                self.OUT.send(DATA)
                                logging.info("CLIENT: OUT Data transfer")
                            else:
                                logging.critical("CLIENT: Verification failed")
                    except Exception as e:
                        logging.error(f"CLIENT: {e}")
                        self.IN.close()
                        self.OUT.close()
                        sys.exit(1)
            except Exception as e:
                logging.critical(f"CLIENT: {e}")
                sys.exit(1)

        def start_OUT(self):
            try:
                while True:
                    try:
                        DATA = self.OUT.recv(1048576)
                        if DATA:
                            DATA = pad(DATA, AES.block_size)
                            DATA = self.LOCKER.encrypt(DATA)
                            VERIFY = hmac.new(self.VERIFY_KEY, DATA, hashlib.sha256).hexdigest().encode()
                            self.IN.send(VERIFY)
                            self.IN.send(DATA)
                            logging.info("CLIENT: IN Data transfer")
                    except Exception as e:
                        logging.error(f"CLIENT: {e}")
                        self.IN.close()
                        self.OUT.close()
                        break
            except Exception as e:
                logging.critical(f"CLIENT: {e}")
                sys.exit(1)