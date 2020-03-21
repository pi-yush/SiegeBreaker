import time
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from utils.constants import *

'''
Utility functions for sending email via web-based gmail.
'''

"""
Sends 1 email as per supplied arguments.
       Parameters
       ----------
       sender_email : str
           Sender's email 
       sender_passwd : str
           Sender's email password
        recv_email : str
           Receiver's email   
       subject_txt : str
         Text to be included as "subject" via sending email
       body_txt : str
           Text to be included as "body" via sending email
       Returns
       ----------
       Bool code representing status of function.   
"""
def send_mail(sender_email, sender_passwd, recv_email, subject_txt, body_txt, browser):
    wait = WebDriverWait(browser, 10)
    # Compose Email Button
    ts = time.time()
    composeElem =  wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'z0')))
    #print "time to login" + str(time.time() - ts_start)
    composeElem.click()


    # To Button
    toElem =  wait.until(EC.element_to_be_clickable((By.NAME, 'to')))
    toElem.send_keys(recv_email)

    subjElem =  wait.until(EC.element_to_be_clickable((By.NAME, 'subjectbox')))
    subjElem.send_keys(subject_txt)

    bodyElem =  wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'editable')))
    bodyElem.send_keys(body_txt)

    upper_send =  wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'btC')))

    inner_Send = upper_send.find_elements(By.TAG_NAME, 'td')

    actual_send = inner_Send[0]

    actual_send.click()
    time.sleep(0.5)
    print "compose and send" + str(time.time() - ts)
    return True;


"""
Logs-in via web based gmail elient and sends 1 email as per supplied arguments.
       Parameters
       ----------
       sender_email : str
           Sender's email 
       sender_passwd : str
           Sender's email password
        recv_email : str
           Receiver's email   
       subject_txt : str
         Text to be included as "subject" via sending email
       body_txt : str
           Text to be included as "body" via sending email
       browser : web driver
           Selenium web driver instance    
       Returns
       ----------
       Bool code representing status of function.   
"""
def login_send_mail(sender_email, sender_passwd, recv_email, subject_txt, body_txt, browser):
    try:
	ts_start = time.time()
        browser.get(GMAIL_WEBSITE)

	wait = WebDriverWait(browser, 10)
	emailElem = wait.until(EC.element_to_be_clickable((By.ID, 'identifierId')))
        emailElem.send_keys(sender_email)

	next = wait.until(EC.element_to_be_clickable((By.ID, 'identifierNext')))
        next.click()

	passwordElem = wait.until(EC.element_to_be_clickable((By.NAME, 'password')))
        passwordElem.send_keys(sender_passwd)
        passwordElem.submit()

        # Passwd Next Button
	passnext = wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'CwaK9')))
        passnext.click()
	
	print "time to login" + str(time.time() - ts_start)
	
        # Now I am logged in
        return send_mail(sender_email, sender_passwd, recv_email, subject_txt, body_txt, browser)

    except Exception as ex:
        print(str(ex))
    finally:
        return True


if __name__ == '__main__':
    browser = webdriver.Chrome()

    login_send_mail(CLIENT_MAIL, CLIENT_MAIL_PASSWD, CONTROLLER_EMAIL, "WHATEVER", "fsdfsdfsdf2", browser);

    print("Main called")
