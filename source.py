#!/usr/bin/env python

'''
  NorseFire Secure Messaging System
'''

import socket
import sys
import subprocess
import re
import hmac
import hashlib
import struct
from thread import *
from time import sleep

secretKey = "[REDACTED]"								# TODO: Set really long string
flag = "\r\n\r\nnotaflag={totally_not_a_flag}"						# For unknown reasons
message = "[REDACTED]"									# Message string
HOST = ''   										# sms.badge.crikey.ctf
PORT = 8888 										# Arbitrary non-privileged port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)				# Define a Socket in Python

try:											# Attempt to bind to specified host/port
    s.bind((HOST, PORT))								
except socket.error as msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]		# or error with output
    sys.exit()

s.listen(10)										# Maintain socket in listen state
											
def TOTP(K, digits=6, window=30, clock=None, digestmod=hashlib.sha1):			# Time Based One-Time-Password function
    C = int(clock / window)                                                                                                                                                    
    return HOTP(K, C, digits=digits, digestmod=digestmod) 
											
def HOTP(K, C, digits=6, digestmod=hashlib.sha1):					# HMAC One-Time Password function
    C_bytes = struct.pack(b"!Q", C)
    hmac_digest = hmac.new(key=K, msg=C_bytes, digestmod=digestmod).hexdigest()
    return Truncate(hmac_digest)[-digits:]
											
def Truncate(hmac_digest):								# Function to truncate the HMAC output
    offset = int(hmac_digest[-1], 16)
    binary = int(hmac_digest[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
    return str(binary)

def xor(plain, k):									# Function to XOR two strings together
    cipher = bytearray()
    for i in xrange(len(plain)):
        cipher.append(chr(plain[i]^k[i%len(k)]))
    return cipher
											
def clientthread(conn):									# Function that executes the vSecurity Messaging Service
    # Banner message for connecting clients
    prompt = subprocess.Popen(["uname","-morn"], stdout=subprocess.PIPE).communicate()[0].rstrip()
    conn.send("\n > " + prompt + "\n\
                                                  \n\
   ####  ####  ##########                         \n\
   ####  ####  ##########      Welcome to the     \n\
   ####  ####  ##########        NorseFire*       \n\
                                                  \n\
   ####  ####  ##########     Secure Messaging    \n\
   ####  ####  ##########          System         \n\
   ####  ####  ##########                         \n\
                                                  \n\
 > Please provide your local Date and Time:\n > ")

    data = conn.recv(17)								# Limits data received to accepted length
    secretMessage = bytearray(message + 	flag)					# Define the message to send
    otp = bytearray(1)									# Initialise the otp variable
    remoteTime = 1									# Initialise the remoteTime variable

    if not re.match("^[0-9]{8} [0-9]{2}:[0-9]{2}:[0-9]{2}$", data):			# Regex match to ensure the date meets the specified date format
        conn.sendall(" > Incorrect Format - Format is YYYYMMDD HH:MM:SS. Goodbye\r\n")	
        conn.close()									# or exit the process
        return

    # Check to ensure supplied date is permitted or exit
    try:
	# Attempt to synchronise time with the connecting clients
        checkValidTime = int(subprocess.Popen(["date","-u","-s",data,"+%s"], stdout=subprocess.PIPE).communicate()[0].rstrip())
    except:
        conn.sendall(" > Hackers detected. This incident will be reported.\r\n") 	# TODO: Hire people to look at the logs
        conn.close()
        return

    conn.send(" > Syncing to remote time...")						# Update user that the input has been received and processed
    sleep(1)										# Allow time for syncing to occur
    remoteTime = int(subprocess.Popen(["date","-u","+%s"], stdout=subprocess.PIPE).communicate()[0].rstrip())	# Set remoteTime to current date time
    if remoteTime > 0:									# Create One-Time Password code for transaction
        otp = bytearray(TOTP(secretKey, 5,5,remoteTime,hashlib.sha512))

    replyString = xor(secretMessage,bytearray(otp)).decode().encode('base64').strip().replace("\n","")	# XOR message with One-Time Password and encode with binary safe format
    buildStrings = [replyString[i:i+32] for i in range(0, len(replyString), 32)]
    reply = "\n > Department Updates:\n"
    for i in range(0, len(buildStrings)):
        reply += "   " + buildStrings[i] + "\n"
    reply += " > Goodbye.\r\n\r\n"

    conn.sendall(reply)									# Send message to connecting client
    conn.close()									# Close connection
    subprocess.Popen(["date","-u","-s","20000101 00:00:00","+%s"])			# Configure system time to arbitrary date and time
    return

while 1:										# Execute threads for connecting clients to listening socket
    conn, addr = s.accept()
    print 'Connected with ' + addr[0] + ':' + str(addr[1])
    start_new_thread(clientthread ,(conn,))

s.close()										# Close Python socket
