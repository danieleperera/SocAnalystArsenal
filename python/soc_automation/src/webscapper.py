from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import NoSuchElementException
import time
from __init__ import drivers
import os

# import getpass

# shift + alt + f to beautifu json

# -------START OF SCRIPT--------
def get_info():
    
    # Create a chrome session
    DRIVERpath = os.path.join(drivers, "chromedriver.exe")

    browser = webdriver.Chrome(DRIVERpath)
    browser.get('https://users.yoroi.company/#/login')

    # ActionChains
    actionchains = ActionChains(browser)

    browser.find_element_by_xpath('/html/body/login/div/div[3]/form/div[2]/input').send_keys('daniele.perera@cybaze.it')
    browser.find_element_by_xpath('/html/body/login/div/div[3]/form/div[3]/input').send_keys('Nimesh2008!ElisA') # getpass.getpass('Password:')
    browser.find_element_by_xpath('/html/body/login/div/div[3]/form/div[4]/p[1]/input').click()
    time.sleep(5)
     
    try:
        ticket = ''
        while ticket.isdigit() == False:
            ticket = input("What ticket do you want to automate (please insert a number): ")
                
        attackers = browser.find_element_by_css_selector("body > dashboard > div.page-container > div.page-content-wrapper > div > analyst-board > div > attacks-board > attacks-list > div.portlet.grey-silver.box > div.portlet-body > div > smart-table > table > tbody > tr:nth-child({}) > td:nth-child(8)".format(ticket))
        victims = browser.find_element_by_css_selector("body > dashboard > div.page-container > div.page-content-wrapper > div > analyst-board > div > attacks-board > attacks-list > div.portlet.grey-silver.box > div.portlet-body > div > smart-table > table > tbody > tr:nth-child({}) > td:nth-child(9)".format(ticket))
        context = browser.find_element_by_css_selector("body > dashboard > div.page-container > div.page-content-wrapper > div > analyst-board > div > attacks-board > attacks-list > div.portlet.grey-silver.box > div.portlet-body > div > smart-table > table > tbody > tr:nth-child({}) > td:nth-child(10)".format(ticket))
        actionchains.double_click(attackers).perform()
        #time.sleep(10)
        # more_context = browser.find_element_by_css_selector("body > dashboard > div.page-container > div.page-content-wrapper > div > analyst-board > div > attacks-board > attacks-list > div.portlet.grey-silver.box > div.portlet-body > div > smart-table > table > tbody > tr:nth-child({}) > td > attack-details > div > div:nth-child(3) > div:nth-child(2) > div > div.panel-body".format(ticket)).click()

        #print("Attacker " + attackers.text)
        attackersip = attackers.text
        #print("Victim " + victims.text)
        victimip = victims.text
        #print("Context " + context.text)
        context = context.text
        #print(more_context.text)
        info = {
            "Attackers" : attackersip,
            "Victims" : victimip,
            "Context" : context

        }
        #time.sleep(50)
        #print(info)
        return(info)
    
    except NoSuchElementException:
        print("Ticket not found")
        pass
