#!/usr/bin/env python

'''
  NorseFire Secure Messaging System
'''

import socket
import threading
import time
import logging
import json
import subprocess
import re
import hmac
import hashlib
import struct
from threading import Thread, Lock
from time import sleep

mutex = Lock()
secretKey = "[REDACTED]"
flag = "\r\n\r\nNotaFlag={like seriously not a flag}"
message = ""
badIP = []
ips = []
address = ""
otp = bytearray(1)


class Crypto(object):

    def TOTP(self, K, digits=6, window=30, clock=None, digestmod=hashlib.sha1):
        C = int(clock / window)
        return self.HOTP(K, C, digits, digestmod)

    def HOTP(self, K, C, digits, digestmod=hashlib.sha1):
        C_bytes = struct.pack(b"!Q", C)
        hmac_digest = hmac.new(key=K, msg=C_bytes, digestmod=digestmod).hexdigest()
        return self.Truncate(hmac_digest)[-6:]

    def Truncate(self, hmac_digest):
        offset = int(hmac_digest[-1], 16)
        binary = int(hmac_digest[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
        return str(binary)

    def xor(self, plain, k):
        cipher = bytearray()
        for i in xrange(len(plain)):
            cipher.append(chr(plain[i]^k[i%len(k)]))
        return cipher


class Logic(object):

    def isBadIP(self,addr):
        global badIP
        global ips
        if addr in [i[0] for i in badIP]:
            if (time.clock() - float([i for i in badIP][0][1])) > 0.01485:
                badIP = [i for i in badIP if i[0] != addr]
                ips = [i for i in ips if i[0] != addr]
                return False, ips, badIP
            else:
                return True, ips, badIP
        else:
            return False, ips, badIP

    def connection(self, addr):
        global ips
        global badIP
        recordedConnections = [i for i in ips if i[0] == addr]
        if len(recordedConnections) > 2:
            if ((float(recordedConnections[-1][1])-float(recordedConnections[0][1])) > 0.044 or len(recordedConnections) >= 6):
                badIP.append((addr,) + (str(float("{0:.4f}".format(time.clock()))),))
                return True, ips, badIP
        if len(ips) > 0:
            if (time.clock() - float(ips[0][1])) >= 0.045:
                ips = []
        return False, ips, badIP

    def banner(self, conn):
        global message
        global flag
        global secretMessage
        prompt = subprocess.Popen(["uname","-morn"], stdout=subprocess.PIPE).communicate()[0].rstrip()
        conn.send("\n > " + prompt + "\n\
                                                     \n\
   ####  ####  ##########                            \n\
   ####  ####  ##########        Welcome to the      \n\
   ####  ####  ##########          NorseFire^        \n\
                                                     \n\
   ####  ####  ##########       Secure Messaging     \n\
   ####  ####  ##########            System          \n\
   ####  ####  ##########                            \n\
                                                     \n\
 > UNAUTHORIZED ACCESS TO THIS SERVICE IS PROHIBITED \n\
 > You *must* have explicit authorized permission to \n\
 > access this service by the Dept of the Fingermen. \n\
 > Abuse and or willful misuses of this service will \n\
 > result in prosecution by the Norsefire Party.     \n\
 >                                                   \n\
 > Actions performed on this service are monitored & \n\
 > logged.                                           \n\
 >                                                   \n\
 > Please provide your local Date and Time:\n > ")
        data = ""
        data = conn.recv(17)
        secretMessage = bytearray(message + flag)
        remoteTime = 1
        if not re.match("^[0-9]{8} [0-9]{2}:[0-9]{2}:[0-9]{2}$", data):
            return False, secretMessage, data
        else:
            return True, secretMessage, data

    def processData(self, secretMessage, data, conn):
        global secretKey
        global otp
        try:
            checkValidTime = int(subprocess.Popen(["date","-u","-s",data,"+%s"], stdout=subprocess.PIPE).communicate()[0].rstrip())
        except:
            reply = ""
            return False, reply
        conn.send("\r\n > Syncing to remote time...\r\n")
        sleep(1)
        remoteTime = int(subprocess.Popen(["date","-u","+%s"], stdout=subprocess.PIPE).communicate()[0].rstrip())
        if remoteTime > 0:									# Good thing time can never be negative right??
            otp = bytearray(Crypto().TOTP(secretKey, 5,5,remoteTime,hashlib.sha512))
        replyString = Crypto().xor(secretMessage,bytearray(otp)).decode().encode('base64').strip().replace("\n","")
        buildStrings = [replyString[i:i+32] for i in range(0, len(replyString), 32)]
        reply = "\r\n > Department Updates:\r\n"
        for i in range(0, len(buildStrings)):
            reply += "   " + buildStrings[i] + "\n"
        reply += " > Goodbye.\r\n\r\n"
        otp = bytearray(1)
        return True, reply


class ThreadedServer(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            print 'Connected with ' + address[0] + ':' + str(address[1])
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        newConnection = (str(address[0]),) + (str(float("{0:.4f}".format(time.clock()))),)
        ips.append(newConnection)
        try:
            check = Logic().isBadIP(address[0])
            if (check[0] == False) and (address[0] not in [i[0] for i in badIP]):
                check = Logic().connection(address[0])
                if (check[0] == True) or (address[0] in [i[0] for i in badIP]):
                    client.send(" > Number of connections exceeded rate limiter. Suspicious IP detected.\r\n")
                    client.close()
                else:
                    check = Logic().banner(client)
                    if (check[0] == True) and (address[0] not in [i[0] for i in badIP]):
                        mutex.acquire()
                        check = Logic().processData(check[1], check[2], client)
                        if (check[0] == True) and (address[0] not in [i[0] for i in badIP]):
                            deliver = check[1]
                            subprocess.Popen(["date","-u","-s","20000101 00:00:00","+%s"])
                        else:
                            client.send("\r\n > An error occured. Please try again later.\r\n") # TODO: Hire people to look at the logs
                            client.close()
                            subprocess.Popen(["date","-u","-s","20000101 00:00:00","+%s"])
                        mutex.release()
                    else:
                        client.send("\r\n > Incorrect Format - Format is YYYYMMDD HH:MM:SS. Goodbye\r\n")
                        client.close()
            else:
                client.send ("")
                client.close()
            client.send(" > Retrieving messages now...")
            sleep(3)
            if (address[0] not in [i[0] for i in badIP]):
                client.send(deliver)
                client.close()
            else:
                client.send("")
                client.close()
        except:
            client.close()
            return False


if __name__ == "__main__":
    while True:
        port_num = 8888
        try:
            port_num = int(port_num)
            break
        except ValueError:
            pass

    ThreadedServer('',port_num).listen()
