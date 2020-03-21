
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from webmail.utils.constants import *


'''
Example code to demonstrate webdriver usage for sending. Please note that this code has nothing to do with SiegeBreaker protocol.
It's sole purpose is to act as practice-ground, when - god forbid - something breaks.
'''

SIEGEBREAKER_SUB = "SiegeBreaker"

browser = webdriver.Chrome()
browser.get('https://www.gmail.com')

time.sleep(4)

emailElem = browser.find_element_by_id('identifierId')

EMAIL = CLIENT_MAIL
PASSWD = CLIENT_MAIL_PASSWD

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

    # for i in range(6):
    #     try:
    #         x  = itd[i].find_element_by_class_name('bA4')
    #         if x:
    #             print x.text
    #             print i
    #     except Exception as e:
    #         print(".")


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


