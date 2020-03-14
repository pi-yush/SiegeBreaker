
#Create 10 connections to server
import email

from imapclient import IMAPClient

from webmail.optimized.sgb_thread import SgbThread
from webmail.utils.constants import CONTROLLER_EMAIL_PASSWD, CONTROLLER_EMAIL, PING_A_SUBJECT

g_server_objects = []
#g_inbox_folder = []
g_next_UID = -1
g_uid_left = 0
g_next_avail_server = 0


HOST = 'imap.gmail.com'
USERNAME = CONTROLLER_EMAIL
PASSWORD = CONTROLLER_EMAIL_PASSWD
TIMEOUT = 5
THREAD_COUNT = 10


def initialize():
    global g_server_objects
    #global g_inbox_folder
    for i in range(THREAD_COUNT):
        server = IMAPClient(HOST)
        server.login(USERNAME, PASSWORD)
        inbox_folder = server.select_folder('INBOX')
        g_server_objects.append(server)
        #g_inbox_folder.append(inbox_folder)



def mark_next_avail_server():
    global g_next_avail_server
    global g_next_UID
    global g_server_objects

    g_next_avail_server = g_next_avail_server % THREAD_COUNT

    # TODO Hack to make it work
    g_server_objects[g_next_avail_server].fetch( [g_next_UID], 'FLAGS')
    # I should remove it

    thread = SgbThread(g_next_UID, g_server_objects[g_next_avail_server] , PING_A_SUBJECT , g_next_avail_server)

    g_next_avail_server = g_next_avail_server + 1
    g_next_UID = g_next_UID + 1
    thread.start()


def main():
    global g_next_UID
    initialize()
    server = IMAPClient(HOST)
    server.login(USERNAME, PASSWORD)
    inbox_folder = server.select_folder('INBOX')
    g_next_UID = inbox_folder['UIDNEXT']


    # Start IDLE mode
    server.idle()
    print("Connection is now in IDLE mode, send yourself an email or quit with ^c")

    while True:
        try:
            responses = server.idle_check(timeout=TIMEOUT)
            #print("Server sent:", responses if responses else "nothing")
            if responses:
                print('Server len(' + str(len(responses)) + ")->" + ' '.join( str(x) for x in responses ))
                for iR in responses:
                    if(iR[1] == 'EXISTS'):
                        mark_next_avail_server()
            else:
                print('...')
        except KeyboardInterrupt:
            break

    server.idle_done()
    print("\nIDLE mode done")
    server.logout()





if __name__ == '__main__':
    main()