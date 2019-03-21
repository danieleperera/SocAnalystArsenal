from selenium import webdriver
import getpass


browser = webdriver.Chrome(r'C:\Users\daniele.perera.CYBAZE\Desktop\progetti vari\blueteam_tools\python\chromedriver.exe')
browser.get('')

browser.find_element_by_xpath('/html/body/login/div/div[3]/form/div[2]/input').send_keys('daniele.perera@cybaze.it')
browser.find_element_by_xpath('/html/body/login/div/div[3]/form/div[3]/input').send_keys(getpass.getpass('Password:'))
browser.find_element_by_xpath('/html/body/login/div/div[3]/form/div[4]/p[1]/input').click()