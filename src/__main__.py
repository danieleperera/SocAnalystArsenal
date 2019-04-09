import filestream
import os
import tempfile
import pyperclip
from win10toast import ToastNotifier
from __init__ import SRC
import re
from colorama import Fore
import argparse
from selenium.common import exceptions

# ===================== ************* =================================
# ----------------- main func do these things -------------------------
#  seek for webscapper python file 
#  1. if exists use it to gather info
#  2. if not exists use import argparse and asks user to insert ip addrs
#  3. Complete manual mode [x]
# selenium.common.exceptions.StaleElementReferenceException
# ===================== ************* =================================


def main():
    
    print(Fore.CYAN + filestream.print_banner())

    parser = argparse.ArgumentParser()

    parser.add_argument('-m', '--manual-mode', action='store_false',
                        default=True,
                        dest='boolean_switch',
                        help='To enter manual mode use this option')

    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')

    parser.add_argument('--ip', action='append', default=[],
                        dest='ip',
                        help='give a list of potential malicious ip addresses')

    parser.add_argument('--sha', action='append', dest='sha_collection',
                        default=[],
                        help='Add SHA values to a list')
    results = parser.parse_args()

    # Argparse default siem exist
    if results.boolean_switch:
        # check if file webscapper exsist to get data from it
        Webscapperpath = os.path.join(SRC, "webscapper__s.py")
        exists = os.path.isfile(Webscapperpath)
        if exists:
            import webscapper
            try:
                collector(webscapper.get_info())
            except exceptions.StaleElementReferenceException:
                print("Error Occured... Entering manual mode")
                manual_mode_ip(results.ip)
            # Testing purposes
            # info = {'attackers': {'124.164.251.179', '179.251.164.124.adsl-pool.sx.cn'}, 'victims': '10.10.2.140', 'context': 'http GET 46.20.95.185'}
        else:
            print("It seems you don't have webscapper on path... Entering manual mode")
            manual_mode_ip(results.ip)

    else:
        print("Entering manual mode")
        # check if argpase values are null
        manual_mode_ip(results.ip)


# ======================= ************* ===============================
# ----------- collector func call the filestream ----------------------
#   1. collect information form APIs 
#   2. create tmp file
#   3. create notification
# ======================== ************* ==============================


def collector(info):
    #info = {'attackers': {'124.164.251.179', '179.251.164.124.adsl-pool.sx.cn'}, 'victims': '10.10.2.140', 'context': 'http GET 46.20.95.185'}
    # ------- Get info about attacker, victim, context from the webscapper -----
    

    # --- Notification ---
    toaster = ToastNotifier()
    # --- * ---

    # --- Clipboard / tmp file ---
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'r+') as tmp:
        # ===================== ************* ===============================
        # ------ IP addresses are getting worked here -----------------------
        # ===================== ************* ===============================
            ip_addresses = get_ip(info)
            #tmp.write(text_header(info))
            for ip in ip_addresses:
                # --- URLscan ---
                urlscan = filestream.ip_urlscan(ip)
                filestream.progressbar_ip(ip_addresses)

                for i in text_body(urlscan):
                    tmp.write(i)
                # --- URLscan end ---
                
                # --- URLhaus ---
                urlhaus = filestream.ip_urlhaus(ip)
                filestream.progressbar_ip(ip_addresses)

                for i in text_body(urlhaus):
                    tmp.write(i)
                # --- URLhaus end ---
                
                # --- AbuseIPdb ---
                abuseipdb = filestream.ip_abuseipdb(ip)
                filestream.progressbar_ip(ip_addresses)

                for i in text_body(abuseipdb):
                    tmp.write(i)
                # --- AbuseIPdb end ---
                
                # --- virustotal ---
                virustotal = filestream.ip_virustotal(ip)
                filestream.progressbar_ip(ip_addresses)

                for i in text_body(virustotal):
                    tmp.write(i)
                # --- virustotal end---
                
        # ===================== ************* ===============================
        # ---------------------- END IP addresses -----------------------
        # ===================== ************* ===============================
            """
            multiple_context = get_context(info).split(" ")[1:]
            for context in tqdm(multiple_context):
                #print(context)
                pass
            """

            tmp.seek(0)
            content = tmp.read()
            if content == '':
                iconBAD = (Fore.RED + '[!]')
                print('\n' + iconBAD + ' No ticket was copied to clipboard')
                print("\n\nRemoving tmp files... Please wait")
            else:
                iconOK = (Fore.GREEN + '[+]')
                print('\n' + iconOK ,end='')
                print(' Ticket was copied to clipboard successfully')
                print("\n\nRemoving tmp files... Please wait")
                pyperclip.copy(content)
                toaster.show_toast("Notifica", "il ticket è stato copiato nella clipboard", duration=10)
                
    finally:
        # print(path)
        os.remove(path)       

# ======================= ************* ===============================
# -------------- Validating information purposes ----------------------
# ======================== ************* ==============================


def get_ip(ip):
    if ip['attackers'] == "":
        print("No attacker ip found...")
    else:
        #print(ip['attackers'])
        return ip['attackers']


def get_context(context):
    if context['context'] == "":
        print("No context found...")
    else:
        return context['context']


def text_header(head):
    test = '''### Attacker\n{0[attackers]}\n### Victim\n{0[victims]}\n### Context\n{0[context]}\n\n'''.format(head)
    print(test)
    return test


def text_body(body):
    try:
        for key, val in body.items():
            yield (('\n{} -> {}').format(key, val))
    except AttributeError:
        pass


def check_ip(ipv4_address):
    #ipv4_address = '& C:/Users/daniele.perera.CYBAZE/.virtualenvs/Soc-L1-Automation-eKL1Fwla/Scripts/activate.ps1'
    test = []
    for i in ipv4_address.split(","):
        #print(i)
        regex_ipv4_public = r"^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$)$" 
        matches_public = re.finditer(regex_ipv4_public, i, re.MULTILINE)

        for x in matches_public:
            test.append(("{match}".format(match=x.group())))
    return test


def manual_mode_ip(ip_addr):
    # check if argpase values are null
    if ip_addr ==[]:
        ip = ''
        while True:
            ip = input('Insert a list of potential malicious ip addresses:')
            if check_ip(ip) == []:
                print("Private / Boradcast / Not valid ip address have been insert, please re-try")
                continue
            else:
                break
        # --- Creating a set ---
        ips = ip.split(",")
        ipss = set(ips)
        # --- End set variable ---
        attackers = {}
        attackers['attackers'] = ipss
        print(attackers)
        collector(attackers)


if __name__ == '__main__':
    main()
