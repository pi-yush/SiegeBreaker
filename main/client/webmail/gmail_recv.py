import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from utils.constants import *
'''
Utility functions for receiving email via web-based gmail.
'''

"""
Finds all emails matching a certain criterion upto "limit"
       Parameters
       ----------
       browser : web driver
           Selenium Web driver instance
       from_who_email : str
           sender email
       subject_txt : str
           Subject text for filtering emails
       limit : int
       Max number of emails in filtered list.  
       Returns
       ----------
       List of emails' body.   
"""
def find_all_mail(browser , from_who_email, subject_txt , limit=10):
    mails = browser.find_elements_by_class_name('zE')
    # mails.click()

    emails_list = []

    index_limit = 0;
    for item in mails:
        # item.click()

        time.sleep(2)
        iTR = item

        itd = iTR.find_elements(By.TAG_NAME, 'td')

        subject = itd[5].find_element_by_class_name('bqe').text

        time.sleep(2)

        if (subject_txt in subject):
            index_limit = index_limit + 1

            if index_limit > limit:
                return emails_list

            iEmailId = iTR.find_elements_by_class_name('bA4')[1].find_element_by_class_name('zF').get_attribute('email')

            iTR.click()
            time.sleep(2)

            body2 = browser.find_element_by_xpath(
                '/html/body/div[7]/div[3]/div/div[2]/div[1]/div[2]/div/div/div/div/div[2]/div/div[1]/div/div[2]/div/table/tr/td[1]/div[2]/div[2]/div/div[3]/div/div/div/div/div/div[1]/div[2]/div[3]/div[3]/div/div[1]')

            print(body2.text)

            print("###################")

            time.sleep(2)



            emails_list.append( body2.text )

            browser.back()


    return emails_list


"""
Finds ONE email matching a certain criterion and returns same"
       Parameters
       ----------
       browser : web driver
           Selenium Web driver instance
       from_who_email : str
           sender email
       subject_txt : str
           Subject text for filtering emails
       Returns
       ----------
       ONE Email's body.   
"""
def find_single_mail( from_who_email, subject_txt , browser):
    wait = WebDriverWait(browser, 100)
    mail = wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'zE')))
    mails = browser.find_elements_by_class_name('zE')
    toReturn = None

    for item in mails:
        iTR = item
        itd = iTR.find_elements(By.TAG_NAME, 'td')
        subject = itd[5].find_element_by_class_name('bqe').text
        if (subject_txt in subject):
            iTR.click()
            #time.sleep(2)
    	    body2 = wait.until(EC.element_to_be_clickable((By.XPATH, '/html/body/div[7]/div[3]/div/div[2]/div[1]/div[2]/div/div/div/div/div[2]/div/div[1]/div/div[2]/div/table/tr/td[1]/div[2]/div[2]/div/div[3]/div/div/div/div/div/div[1]/div[2]/div[3]/div[3]/div/div[1]')))
            print(body2.text)
            toReturn =  (body2.text + '.')[:-1]
            browser.back()
            break;
    return toReturn

"""
Logs in to gmail and receives all emails matching a certain criterion"
       Parameters
       ----------
       browser : web driver
           Selenium Web driver instance
       from_who_email : str
           sender email
       subject_txt : str
           Subject text for filtering emails
       recv_email : str
           Email ID to be used for login into gmail website
       recv_passwd : str
           Password to be used for login.    
       Returns
       ----------
       All Email's body and email ids.   
"""
def login_recv_all_mail(recv_email, recv_passwd,  from_who_email , subject_txt, browser):
    g_emails_list = []
    g_email_ids = []
    wait = WebDriverWait(browser, 10)
    try:
        browser.get(GMAIL_WEBSITE)

        emailElem = wait.until(EC.element_to_be_clickable((By.ID, 'identifierId')))
        emailElem.send_keys(recv_email)

        next = wait.until(EC.element_to_be_clickable((By.ID, 'identifierNext')))
        next.click()

        passwordElem = wait.until(EC.element_to_be_clickable((By.NAME, 'password')))
        passwordElem.send_keys(recv_passwd)
        passwordElem.submit()

        # Passwd Next Button
        passnext = wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'CwaK9')))
        passnext.click()
        emailwait = WebDriverWait(browser, 100)

	mail = emailwait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'zE')))
	mails = browser.find_elements_by_class_name('zE')

        index_limit = 0;
        for item in mails:
            iTR = item

            itd = iTR.find_elements(By.TAG_NAME, 'td')
            iEmailId = iTR.find_elements_by_class_name('bA4')[1].find_element_by_class_name('zF').get_attribute('email')


            subject = itd[5].find_element_by_class_name('bqe').text

            if (subject_txt in subject):


                if index_limit > LIMIT_UNREADMAIL:
                    print("Exception::LIMIT REACHED" + LIMIT_UNREADMAIL)
                    return g_emails_list

                iTR.click()
                body2 = wait.until(EC.element_to_be_clickable((By.XPATH, '/html/body/div[7]/div[3]/div/div[2]/div[1]/div[2]/div/div/div/div/div[2]/div/div[1]/div/div[2]/div/table/tr/td[1]/div[2]/div[2]/div/div[3]/div/div/div/div/div/div[1]/div[2]/div[3]/div[3]/div/div[1]')))
                toAdd = (body2.text + '.')[:-1]
                g_emails_list.append( toAdd )
                g_email_ids.append(iEmailId)
                index_limit = index_limit + 1
                browser.back()
            else:
                print('...')

       # return emails_list


    except Exception as ex:
        print("Exception::")
        print(str(ex))
    finally:
        return g_emails_list , g_email_ids


def login_recv_single_mail(recv_email, recv_passwd,  from_who_email , subject_txt, browser):
    try:
        browser.get(GMAIL_WEBSITE)

        wait = WebDriverWait(browser, 10)
        emailElem = wait.until(EC.element_to_be_clickable((By.ID, 'identifierId')))
        emailElem.send_keys(recv_email)

        next = wait.until(EC.element_to_be_clickable((By.ID, 'identifierNext')))
        next.click()

        passwordElem = wait.until(EC.element_to_be_clickable((By.NAME, 'password')))
        passwordElem.send_keys(recv_passwd)
        passwordElem.submit()

        # Passwd Next Button
        passnext = wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'CwaK9')))
        passnext.click()

	# Now I am logged in

        return find_single_mail( from_who_email, subject_txt)

    except Exception as ex:
        print(str(ex))
    finally:
        return None


if __name__ == '__main__':

   browser = webdriver.Chrome()
   print("Main called")

