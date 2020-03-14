import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from utils.constants import *


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



def find_single_mail( from_who_email, subject_txt , browser):
    wait = WebDriverWait(browser, 100)
    mail = wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'zE')))
    mails = browser.find_elements_by_class_name('zE')
    # mails.click()
    toReturn = None

    for item in mails:
        # item.click()

        #time.sleep(2)
        iTR = item

        itd = iTR.find_elements(By.TAG_NAME, 'td')

        subject = itd[5].find_element_by_class_name('bqe').text
        iEmailId = iTR.find_elements_by_class_name('bA4')[1].find_element_by_class_name('zF').get_attribute('email')

        #time.sleep(2)

        if (subject_txt in subject) and (iEmailId.strip() == from_who_email.strip()):
            iTR.click()
            #time.sleep(2)

	    body2 = wait.until(EC.element_to_be_clickable((By.XPATH, '/html/body/div[7]/div[3]/div/div[2]/div[1]/div[2]/div/div/div/div/div[2]/div/div[1]/div/div[2]/div/table/tr/td[1]/div[2]/div[2]/div/div[3]/div/div/div/div/div/div[1]/div[2]/div[3]/div[3]/div/div[1]')))

            #body2 = browser.find_element_by_xpath(
            #    '/html/body/div[7]/div[3]/div/div[2]/div[1]/div[2]/div/div/div/div/div[2]/div/div[1]/div/div[2]/div/table/tr/td[1]/div[2]/div[2]/div/div[3]/div/div/div/div/div/div[1]/div[2]/div[3]/div[3]/div/div[1]')

            print(body2.text)

            print("###################")


            toReturn =  (body2.text + '.')[:-1]

            browser.back()
            #time.sleep(2)

            break;

    return toReturn


def login_recv_all_mail(recv_email, recv_passwd,  from_who_email , subject_txt, browser):
    g_emails_list = []
    g_email_ids = []
    wait = WebDriverWait(browser, 10)
    try:
        browser.get(GMAIL_WEBSITE)

        #wait = WebDriverWait(browser, 10)
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

        emailwait = WebDriverWait(browser, 100)
	mail = emailwait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'zE')))
	mails = browser.find_elements_by_class_name('zE')
        # mails.click()



        index_limit = 0;
        for item in mails:
            # item.click()

            #time.sleep(2)
            iTR = item

            itd = iTR.find_elements(By.TAG_NAME, 'td')
            iEmailId = iTR.find_elements_by_class_name('bA4')[1].find_element_by_class_name('zF').get_attribute('email')


            subject = itd[5].find_element_by_class_name('bqe').text

            #time.sleep(2)

            if (subject_txt in subject):


                if index_limit > LIMIT_UNREADMAIL:
                    print("Exception::LIMIT REACHED" + LIMIT_UNREADMAIL)
                    return g_emails_list , g_email_ids


                # sender_id = browser.find_element_by_css_selector('#\3a 7y > div.adn.ads > div.gs > div.gE.iv.gt > table > tbody > tr:nth-child(1) > td.gF.gK > table > tbody > tr > td > h3 > span > span.gD')
                # print(sender_id.text)
                #


                iTR.click()
                #time.sleep(2)
		
		body2 = wait.until(EC.element_to_be_clickable((By.XPATH, '/html/body/div[7]/div[3]/div/div[2]/div[1]/div[2]/div/div/div/div/div[2]/div/div[1]/div/div[2]/div/table/tr/td[1]/div[2]/div[2]/div/div[3]/div/div/div/div/div/div[1]/div[2]/div[3]/div[3]/div/div[1]')))
                #body2 = browser.find_element_by_xpath(
                #    '/html/body/div[7]/div[3]/div/div[2]/div[1]/div[2]/div/div/div/div/div[2]/div/div[1]/div/div[2]/div/table/tr/td[1]/div[2]/div[2]/div/div[3]/div/div/div/div/div/div[1]/div[2]/div[3]/div[3]/div/div[1]')


                # toAdd = body2.text;

                toAdd = (body2.text + '.')[:-1]

                print("###################")

                #time.sleep(2)

                g_emails_list.append( toAdd )
                g_email_ids.append(iEmailId)

                #print(emails_list[index_limit])

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


'''

SIEGEBREAKER_SUB = "SiegeBreaker"

browser = webdriver.Chrome()
browser.get('https://www.gmail.com')

time.sleep(4)

emailElem = browser.find_element_by_id('identifierId')

EMAIL = ""
PASSWD = ""

emailElem.send_keys(EMAIL)


next = browser.find_element_by_id('identifierNext')
if next:
    next.click()

# emailElem.submit()

time.sleep(2)

passwordElem = browser.find_element_by_name("password")  # .sendKeys("Password");#browser.find_element_by_id('pstMsg')
passwordElem.send_keys(PASSWD)

passwordElem.submit()

# time.sleep(4)

# next = browser.find_element_by_id('identifierNext')
# if next:
#        next.click()

composeElem = browser.find_element_by_class_name("CwaK9")  # this only works half of the time
composeElem.click()

time.sleep(7)

# browser.get("https://mail.google.com/mail/u/0/#all")

mails = browser.find_elements_by_class_name('zE')
# mails.click()

for item in mails:
    #item.click()

    time.sleep(2)
    iTR = item

    itd = iTR.find_elements(By.TAG_NAME, 'td')

    subject = itd[5].find_element_by_class_name('bqe').text

    time.sleep(2)

    print("Subject Processed" + subject)
    if( SIEGEBREAKER_SUB in subject ):

        iTR.click()
        time.sleep(2)

        body2 = browser.find_element_by_xpath(
            '/html/body/div[7]/div[3]/div/div[2]/div[1]/div[2]/div/div/div/div/div[2]/div/div[1]/div/div[2]/div/table/tr/td[1]/div[2]/div[2]/div/div[3]/div/div/div/div/div/div[1]/div[2]/div[3]/div[3]/div/div[1]')

        print(body2.text)

        print("###################")


        time.sleep(2)
        browser.back()
        
        
'''
