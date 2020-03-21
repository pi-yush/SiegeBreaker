#!/usr/bin/python
import cPickle
import json

from scapy.layers.inet import ICMP, IP
import gmail_send
from selenium import webdriver

from scapy.all import *
import sys
import binascii
from random import randint
from Crypto.PublicKey import RSA
from datetime import datetime

import time

import sys
from utils.constants import *
from utils.crypt import get_encrypted_content
from utils.crypt import seccure_get_decrypted_content

#from webmail 
import gmail_recv

'''
Code used to send email to Center/Proxy's email handle. As of now, Chrome is being used for email communication.
 A user may use Firefox, with little tweaks in below code.
'''
def main(argv):

    if len(argv) != 5:
        print('usage: ./<name>.py <OD2 IP Address> <OD1 IP Address> <TimeoutInSeconds> <src_port> Your Len ' + str(
            len(argv)))
        exit(1)

    OD2_IP = argv[1]
    OD1_IP = argv[2]
    TIMEOUT = argv[3]
    SRC_PORT = argv[4]
    ISN_NUMBER = str(random.getrandbits(32))


    PUBLIC_KEY , PRIVATEKEY = crypt.get_ec_public_private_key()

    #Construct payload whist mering it with seperators; these seperators will be used to dissemble payload at controller's end.
    payload = MAGIC_WORD + SEP + OD2_IP + SEP + OD1_IP + SEP + TIMEOUT + SEP + SRC_PORT + SEP + ISN_NUMBER + SEP + PUBLIC_KEY + SEP
    #Display email's payload and subject before sending.
    print("Payload : " + CLIENT_A_SUBJECT + " : " + payload)
    #Encrpt payload with Public-Private Crypto.
    cipher_text = get_encrypted_content(payload)

#Be ready with required information, before initiating webdriver.
    sender_email = CLIENT_MAIL
    sender_passwd = CLIENT_MAIL_PASSWD
    recv_email = CONTROLLER_EMAIL
    subject_txt = CLIENT_A_SUBJECT
    body_txt = cipher_text

    chrome_options = webdriver.ChromeOptions()
    #chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    #chrome_options.add_argument('--disable-dev-shm-usage')
    browser = webdriver.Chrome(chrome_options=chrome_options)

    #browser = webdriver.Firefox()
    gmail_send.login_send_mail(sender_email, sender_passwd, recv_email, subject_txt, body_txt, browser);

    print("Email Sent to Controller")
    print("Waiting for Ack.....")
    cipher_text = None
    while cipher_text is None:
        time.sleep(2)
        cipher_text = gmail_recv.find_single_mail(recv_email, CLIENT_A_ACK_SUB, browser)

    print("Waiting Complete")
    plain_text = seccure_get_decrypted_content( cipher_text ,  PRIVATEKEY)

    if plain_text == CLIENT_A_ACK_BODY:
        print("DECOY ROUTING SETUP COMPLETE")
    else:
        print(plain_text + "&&" + CLIENT_A_ACK_BODY)


if __name__ == '__main__':
    main(sys.argv)
