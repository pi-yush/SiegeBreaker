#!/usr/bin/python
from time import sleep

from utils.crypt import seccure_get_encrypted_content, get_decrypted_content
from utils.constants import *
from utils import smtp_helper
from utils import ping

def send_ack_to_client(email_to_send_to , client_public_key):

    body_txt = seccure_get_encrypted_content(CLIENT_A_ACK_BODY , client_public_key)

    smtp_helper.send_mail(CONTROLLER_EMAIL ,CONTROLLER_EMAIL_PASSWD , email_to_send_to , CLIENT_A_ACK_SUB , body_txt )


'''
Function for receiving email via smtplib/imap based gmail on controller side. 
'''
def main():

    print("Initializing....")

    payloads_list , email_id_list = smtp_helper.login_recv_all_mail(CONTROLLER_EMAIL, CONTROLLER_EMAIL_PASSWD, CLIENT_MAIL, CLIENT_A_SUBJECT );

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
            ping.sendPing( passed_args )
            #time.sleep(2)
            send_ack_to_client(email_id_list[index]  , client_public_key)
            #time.sleep(2)



if __name__ == '__main__':
    while True:
        main()
        sleep(10)
