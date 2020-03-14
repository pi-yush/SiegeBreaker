import smtplib
import time
from itertools import chain
import email
import imaplib

import easyimap

import constants



def get_hostname(username):
    if ('hotmail' in username):
        return 'smtp.live.com'
    elif ('gmail' in username):
        return 'smtp.gmail.com'
    elif ('iiitd' in username):
        return 'smtp.gmail.com'
    return None

def get_imap_name(username):
    if ('gmail' in username):
        return 'imap.gmail.com'
    elif ('iiitd' in username):
        return 'imap.gmail.com'
    elif ('hotmail' in username):
        return 'imap.live.com'
    return None

def send_mail(sender_email, sender_passwd, recv_email, subject_txt, body_txt):
    smtp_ssl_host = get_hostname(sender_email)
    msg = email.message_from_string(body_txt)
    msg['From'] = sender_email
    msg['To'] = recv_email
    msg['Subject'] = subject_txt

    s = smtplib.SMTP(smtp_ssl_host, 587)

    s.ehlo()  # Hostname to send for this command defaults to the fully qualified domain name of the local host.
    s.starttls()  # Puts connection to SMTP server in TLS mode
    s.ehlo()
    s.login( sender_email, sender_passwd)
    s.sendmail( sender_email , recv_email, msg.as_string())
    s.quit()

    return True



def login_recv_all_mail(recv_email, recv_passwd,  from_who_email , subject_txt):
    imap_ssl_host = get_imap_name(recv_email)

    g_emails_list = []
    g_email_ids = []

    imapper = easyimap.connect(imap_ssl_host, recv_email, recv_passwd)
    for mail in imapper.unseen(limit=constants.LIMIT_UNREADMAIL):
        #mail = imapper.mail(mail_id)

        if mail.title == subject_txt:
            g_email_ids.append(mail.from_addr)
            g_emails_list.append(mail.body)

    return  g_emails_list , g_email_ids


def login_send_mail(sender_email, sender_passwd, recv_email, subject_txt, body_txt):
    return send_mail(sender_email, sender_passwd, recv_email, subject_txt, body_txt)


def login_find_single_mail(recv_email, recv_passwd , from_who_email ,  subject_txt):
    imap_ssl_host = get_imap_name(recv_email)
    toReturn = None


    imapper = easyimap.connect(imap_ssl_host, recv_email, recv_passwd)
    for mail in imapper.unseen(limit=constants.LIMIT_UNREADMAIL):
        # mail = imapper.mail(mail_id)
        if mail.title == subject_txt and mail.from_addr == from_who_email:
            toReturn = mail.body
            break;

    return toReturn
