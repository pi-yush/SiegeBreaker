import email
import threading

from imapclient import IMAPClient

from webmail.utils import smtp_helper
from webmail.utils.constants import SEP, MAGIC_WORD, PING_A_ACK_BODY, CONTROLLER_EMAIL, CONTROLLER_EMAIL_PASSWD, \
    PING_A_ACK_SUB
from webmail.utils.crypt import get_decrypted_content, seccure_get_encrypted_content


class SgbThread(threading.Thread):

    def __init__(self, iUID , server , subject_text, index):
        threading.Thread.__init__(self)
        self.name = str(index) + '::' + str(iUID)
        self.iUID = iUID
        self.server = server
        self.subject_text = subject_text

    def send_ack_to_client(self, email_to_send_to, client_public_key):
        body_txt = seccure_get_encrypted_content(PING_A_ACK_BODY, client_public_key)
        smtp_helper.send_mail(CONTROLLER_EMAIL, CONTROLLER_EMAIL_PASSWD, email_to_send_to, PING_A_ACK_SUB, body_txt)

    def run(self):
        print("Thread --- BEGIN " + self.name)
        for uid, message_data in self.server.fetch( [self.iUID] , 'RFC822').items():

            email_message = email.message_from_string(message_data[b'RFC822'])
            email_sender = email_message.get('From')
            if self.subject_text == email_message.get('Subject'):
                print('Thread --- Subject Found')
                iPayload = email_message._payload
                argv = get_decrypted_content(iPayload).split(SEP)


                magic_wrd = argv[0]

                if (magic_wrd == MAGIC_WORD):
                    OD2_IP = argv[1]
                    OD1_IP = argv[2]
                    TIMEOUT = argv[3]
                    SRC_PORT = argv[4]
                    ISN_NUMBER = argv[5]

                    client_public_key = argv[6]

                    # Throwing out ISN as of now
                    passed_args = argv[1: 5]

                    print("Add rule to Controller : " + email_sender + "  Send self ping ")

                    print(' '.join(passed_args))

                    #            controller_internal_ping.main( passed_args )

                    # time.sleep(2)
                    # self.send_ack_to_client( email_sender, client_public_key)

                    # time.sleep(2)
            else:
                print("Thread --- Wrong Email")


        print("Thread --- END " + self.name)