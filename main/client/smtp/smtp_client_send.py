#!/usr/bin/python
import random
import time

import sys

from utils import crypt
from utils.constants import *
from utils import smtp_helper
from utils.crypt import get_encrypted_content, seccure_get_decrypted_content

'''
Function for sending email via smtp/imap based email on client side.
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


    payload = MAGIC_WORD + SEP + OD2_IP + SEP + OD1_IP + SEP + TIMEOUT + SEP + SRC_PORT + SEP + ISN_NUMBER + SEP + PUBLIC_KEY + SEP

    print("Payload : " + CLIENT_A_SUBJECT + " : " + payload)
    cipher_text = get_encrypted_content(payload)

    sender_email = CLIENT_MAIL
    sender_passwd = CLIENT_MAIL_PASSWD
    recv_email = CONTROLLER_EMAIL
    subject_txt = CLIENT_A_SUBJECT
    body_txt = cipher_text

    smtp_helper.login_send_mail(sender_email, sender_passwd, recv_email, subject_txt, body_txt);

    print("Email Sent to Controller")
    print("Waiting for Ack.....")

    #time.sleep(30)


    cipher_text = None
    while cipher_text is None:
        time.sleep(2)
        cipher_text = smtp_helper.login_find_single_mail( sender_email , sender_passwd ,recv_email, PING_A_ACK_SUB)


    print("Waiting Complete")
    plain_text = seccure_get_decrypted_content( cipher_text ,  PRIVATEKEY)


    if plain_text == CLIENT_A_ACK_BODY:
        print("DECOY ROUTING SETUP COMPLETE")
    else:
        print(plain_text + "&&" + CLIENT_A_ACK_BODY)




if __name__ == '__main__':
    main(sys.argv)
