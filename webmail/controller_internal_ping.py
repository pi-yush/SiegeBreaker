#!/usr/bin/python

from scapy.all import *
import sys
import binascii
from random import randint
from Crypto.PublicKey import RSA
from datetime import datetime
import seccure
import time


def sendPing(destIP, signalString, times):
    pkt = IP(dst=destIP) / ICMP() / signalString
    for i in range(0, times):
        send(pkt)


def main(argv):
    if len(argv) != 4:
        print 'usage: ./icmpTest.py <OD2 IP Address> <OD1 IP Address> <TimeoutInSeconds> <src_port>'
        exit(1)
    # print argv

    timestamp = int(time.time())

    ## Encrypt someString with controller's public key
    pubkey = b'8W;>i^H0qi|J&$coR5MFpR*Vn'  ## = str(seccure.passphrase_to_pubkey(b'my private key'))

    # if(int(argv[1])<10):
    #	argv[1] = 'Siegebreak000'+argv[1]
    # elif(int(argv[1])<100):
    #	argv[1] = 'Siegebreak00'+ argv[1]
    # elif(int(argv[1])<1000):
    #	argv[1] = 'Siegebreak0'+argv[1]
    # elif(int(argv[1])<10000):
    #	argv[1] = 'Siegebreak' + argv[1]
    # else:
    #	print "Timeout value not permitted; Try again with timeout<10000"
    #	exit(0)

    # argv[1]=argv[1]+'@'+str(timestamp)
    # print argv[1]

    # encryptedString = seccure.encrypt(argv[1], pubkey)

    if (int(argv[2]) < 10):
        argv[2] = 'Siege000' + argv[2]
    elif (int(argv[2]) < 100):
        argv[2] = 'Siege00' + argv[2]
    elif (int(argv[2]) < 1000):
        argv[2] = 'Siege0' + argv[2]
    elif (int(argv[2]) < 10000):
        argv[2] = 'Siege' + argv[2]
    else:
        print "Timeout value not permitted; Try again with timeout<10000"
        exit(0)

    padding = (15 - len(argv[1]));

    argv[2] = argv[2] + '@' + argv[1] + '#' + argv[3] + '$'
    # print argv[2]
    # print argv[2]

    encryptedString = seccure.encrypt(argv[2], pubkey)
    # print len(encryptedString)
    iter = randint(1, 3)
    iter = 1;
    # print iter

    sendPing(argv[0], str(encryptedString), iter)


if __name__ == "__main__":
    main(sys.argv[1:])
