#!/usr/bin/python
import cPickle

from scapy.layers.inet import ICMP, IP
import gmail_recv
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
from utils.crypt import get_decrypted_content
from utils.crypt import get_encrypted_content
from utils.crypt import seccure_get_encrypted_content


import controller_internal_ping
#from webmail 
import gmail_send


def send_ack_to_client(email_to_send_to , browser, client_public_key):

    body_txt = seccure_get_encrypted_content(PING_A_ACK_BODY , client_public_key)


    gmail_send.send_mail(CONTROLLER_EMAIL ,CONTROLLER_EMAIL_PASSWD , email_to_send_to , PING_A_ACK_SUB , body_txt , browser)


def main():

    print("Initializing....")

    chrome_options = webdriver.ChromeOptions()
    #chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    #chrome_options.add_argument('--disable-dev-shm-usage')
    browser = webdriver.Chrome(chrome_options=chrome_options)

    #browser = webdriver.Chrome()
    #browser = webdriver.Firefox()

    payloads_list , email_id_list = gmail_recv.login_recv_all_mail(CONTROLLER_EMAIL, CONTROLLER_EMAIL_PASSWD, CLIENT_MAIL, PING_A_SUBJECT , browser);

    if payloads_list is None:
        print("No emails to process")
        return None
    else:
        print("Processing emails : " + str(len(payloads_list)) )


    for index,iPayload in enumerate(payloads_list):
        argv =  get_decrypted_content( iPayload ).split(SEP)

        magic_wrd = argv[0]

        if(magic_wrd == MAGIC_WORD):
            OD2_IP = argv[1]
            OD1_IP = argv[2]
            TIMEOUT = argv[3]
            SRC_PORT = argv[4]
            ISN_NUMBER = argv[5]

            client_public_key = argv[6]


            #Throwing out ISN as of now
            passed_args = argv[1: 5]

            print("Add rule to Controller : "+  email_id_list[index] +"  Send self ping " )

            print(' '.join(passed_args))

            controller_internal_ping.main( passed_args )

            #time.sleep(2)
            send_ack_to_client(email_id_list[index] , browser , client_public_key)

            #time.sleep(2)



if __name__ == '__main__':
    main()
