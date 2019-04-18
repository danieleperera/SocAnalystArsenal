# -*- coding: utf-8 -*-
# -*- style: PEP8 -*-
import filestream1
import os
import tempfile
import pyperclip
from win10toast import ToastNotifier
from __init__ import SRC
import re
from colorama import Fore, init
import argparse
from selenium.common import exceptions
import time


def main():
    """
    Documentation for main.

    It prints the banner and uses argparse to get data from user.
    If no option is given, it defaults to use webscapper.
    """
    print(Fore.CYAN + filestream1.print_banner())

    parser = argparse.ArgumentParser()

    parser.add_argument('-m', '--manual-mode', action='store_false',
                        default=True,
                        dest='boolean_switch_mode',
                        help='To enter manual mode use this option')

    parser.add_argument('--version', action='version',
                        version='%(prog)s 0.0.1')

    parser.add_argument('--ip', nargs='+', dest='ip',
                        help='give a list of potential malicious ip addresses')

    parser.add_argument('--sha', action='append', dest='sha_sum',
                        default=[],
                        help='Add SHA values to a list')

    parser.add_argument('-v', '--verbose', action='store_false',
                        default=True,
                        dest='bool_vb',
                        help='Use this flag to get full data from APIs')

    results = parser.parse_args()

    # Default to webscapper
    if results.boolean_switch_mode:
        # check if file webscapper exsist to get data from it
        Webscapperpath = os.path.join(SRC, "webscapper_1.py")
        exists = os.path.isfile(Webscapperpath)
        if exists:
            import webscapper
            try:
                # try to get data from webscapper
                # if error occured jump to manual mode
                collector(webscapper.get_info(), verbose_mode(results.bool_vb))
            except exceptions.StaleElementReferenceException:
                print("Error Occured... Entering manual mode")
                manual_mode_ip(results.ip, verbose_mode(results.bool_vb), results.sha_sum)
            # Testing purposes
            # info = {'attackers': {'124.164.251.179',
            #                       '179.251.164.124.adsl-pool.sx.cn'},
            #        'victims': '10.10.2.140',
            #        'context': 'http GET 46.20.95.185'}
            #
        else:
            # Default to webscapper but webscapper isn't in path
            # Enter manual mode
            print("""It seems you don't have webscapper on path...
                    Entering manual mode""")
            manual_mode_ip(results.ip, verbose_mode(results.bool_vb), results.sha_sum)

    else:
        # User entered option to get manual mode
        print("Entering manual mode")
        # check if argpase values are null
        manual_mode_ip(results.ip, verbose_mode(results.bool_vb), results.sha_sum)


def collector(info: dict, verbosity_check: bool, sha_sum_list: list = None):
    """
    Documentation for collector.
    Creates a tmp file and pass the dict to other functions,
    copy data from those functions to the tmp file,
    once done delete the tmp file and gives a desktop notification popup.

    param
        info: dict -- This is a dictionary variable.

    example::

    ```
     info = {'attackers': {'124.164.251.179',
                           '179.251.164.124.adsl-pool.sx.cn'},
            'victims': '10.10.2.140',
            'context': 'http GET 46.20.95.185'}
    ```
    """
    # --- Notification ---
    toaster = ToastNotifier()
    # --- Clipboard / tmp file ---
    fd, path = tempfile.mkstemp()
    #print(sha_sum_list)
    try:
        with os.fdopen(fd, 'r+') as tmp:
            #  ===================== ************* ===========================
            # ------ IP addresses are getting worked here --------------------
            # ===================== ************* ============================
            ip_addresses, domain = check_domain_or_ip(info['attackers'])
            tmp.write(text_header(info))
            #print(ip_addresses)
            #print(domain)
            #
            # --- progress bar ---
            
            iconOK = (Fore.GREEN + '[!]')
            iconNone = (Fore.YELLOW + '[!]')
            init(autoreset=True)
            #  ===================== ************* ===========================
            # ------ Core filestream1 are being worked here --------------------
            # ===================== ************* ============================
            for element in info['attackers']:
                colorIP = (Fore.RED + element)
                if domain == []:
                    # pass ip
                    if ip_addresses == []:
                        # no ip or domain found
                        print('no ip or domain given')
                        pass
                    else:
                        # give ip address
                        # --- virustotal ---
                        print(iconNone, end='')
                        print(' Checking whois information on Virustotal for ' + colorIP)
                        try:
                            whois_info, detected = filestream1.ip_virustotal(element, False)
                        except TypeError:
                            whois_info = filestream1.ip_virustotal(element, False)
                        finally:
                            print(whois_info)
                        header_whois = ('Whois Information ' + element + '\n')
                        tmp.write(header_whois)
                        for i in text_body(whois_info):
                            tmp.write(i)
                        
                        # --- End Virustotal ---
                        # --- Shodan ---
                        print(iconNone, end='')
                        print(' Checking if host is compromised on Shodan.io ' + colorIP)
                        compromised = filestream1.shodan_ip_info(element)
                        header_shodan = ('\n\nShodan Information ' + element + '\n')
                        tmp.write(header_shodan)
                        tableContent_shodan = text_body_table(compromised)
                        tmp.write('\n {} \n'.format(printTable(tableContent_shodan)))
                        # ---End Shodan ---
                        # --- apility --- 
                        print(iconNone, end='')
                        print(' Checking IP reputation through time using apility ' + colorIP)
                        header_apility = ('\n\nApility reputation ' + element + '\n')
                        tmp.write(header_apility)
                        reputation = filestream1.apility_ip_info(element)
                        if reputation is None:
                            string = '\nThis IP has not been blacklisted since 1 year'
                            tmp.write(string)
                            print(string)
                        else:
                            content_list = []
                            content_list.append(list(reputation[0].keys()))
                            for i in range(len(reputation)):
                                tp = reputation[i]['timestamp']
                                date = time.strftime('%Y-%m-%d', time.localtime(tp/1000))
                                reputation[i].update(timestamp = date)
                                content_list.append(list(reputation[i].values()))
                            table_reputation = printTable_row(content_list)
                            tmp.write('\n {} \n'.format(table_reputation))                 
                            pass
                        # --- End apility ---
                else:
                    # pass domain
                    if ip_addresses == []:
                        # pass only domain
                        whois_info, detected_category = filestream1.domain_virustotal(element, False)
                        #print(domain)
                        print(iconNone, end='')
                        print(' Checking whois information on Virustotal for ' + colorIP)
                        print('Domain Name : ' + whois_info['Domain Name'].decode('utf-8'))
                        header_whois = ('Whois Information for this domain: ' + element + '\n')
                        filestream1.progressbar_ip(info['attackers'])
                        tmp.write(header_whois)
                        for i in text_body(whois_info):
                            tmp.write(i)                        
                        #print(detected_category)
                        pass
                    else:
                        # pass domain and ip
                        print('both are here')
                        print(domain)
                        print(ip_addresses)
                        pass
                    pass
            tmp.seek(0)
            content = tmp.read()
            if content == '':
                iconBAD = (Fore.RED + '[!]')
                print('\n' + iconBAD + ' No ticket was copied to clipboard')
                print("\n\nRemoving tmp files... Please wait")
            else:
                iconOK = (Fore.GREEN + '[+]')
                print('\n' + iconOK, end='')
                print(' Ticket was copied to clipboard successfully')
                print("\n\nRemoving tmp files... Please wait")
                pyperclip.copy(content)
        toaster.show_toast("""Ticket copied to clipboard""", duration=10)
    finally:
        # print(path)
        os.remove(path)
# ======================= ************* ===============================
# -------------- Validating information purposes ----------------------
# ======================== ************* ==============================


def get_context(context):
    if context['context'] == "":
        print("No context found...")
    else:
        return context['context']


def text_header(head):
    test = '''\n### Attackers -> {}
### Victims   -> {}
### Context   -> {}\n\n'''.format(
                head.get("attackers", "Not found!"),
                head.get("victims", "Not found!"),
                head.get("context", "Not found!"))
    print(test)
    return test


def text_body(body):
    try:
        for key, val in body.items():
            yield (('\n{} -> {}').format(key, val))
    except AttributeError:
        pass


def text_body_table(body):
    try:
        for key, val in body.items():
            yield (('{}, {}').format(key, val))
    except AttributeError:
        pass


def check_domain_or_ip(data):
    ip = []
    for i in data:
        # print(i)
        regex_ipv4_public = r"^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$)$"
        matches_public = re.finditer(regex_ipv4_public, i, re.MULTILINE)
        for x in matches_public:
            ip.append(("{match}".format(match=x.group())))
    #print(ip)
    domain = []
    for z in data:
        #print(z)
        regex_domain = r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
        matches_domain = re.finditer(regex_domain, z, re.MULTILINE)
        for f in matches_domain:
            domain.append(("{match}".format(match=f.group())))
    #print(domain)
    return ip, domain


def manual_mode_ip(ip_addr: list, verbosity: bool, sha_sum: list = None):
    # check if argpase values are null
    if ip_addr is None:
        ip = ''
        while True:
            ip = input('Insert a list of potential malicious ip addresses:')
            if check_ip(ip) == []:
                print("Not valid ip address have been insert, please re-try")
                continue
            else:
                break
        # --- Creating a set ---
        ips = ip.split(",")
        ipss = set(ips)
        # --- End set variable ---
        attackers = {}
        attackers['attackers'] = ipss
        #print(attackers)
        collector(attackers, verbosity)
    else:
        # --- Complete manual mode ---
        #print("Sono qua e sono da solo ")
        #print(ip_addr)
        for ip in ip_addr:
            ipss = set(ip_addr)
        attackers = {}
        attackers['attackers'] = ipss
        #print(attackers)
        if sha_sum == []:
            return collector(attackers, verbosity)
        else:
            return collector(attackers, verbosity, sha_sum)
        pass


def verbose_mode(verbosity: bool) -> bool:
    if verbosity:
        #print("Flag non c'è")   verbosity minima
        return False
    else:
        #print("Flag c'è")   verbosity massima
        return True


def printTable(tbl, borderHorizontal='-', borderVertical='|', borderCross='+'):
    # get the columns split by the values
    cols = [col.split(', ') for col in tbl]

    # find the longests strings
    string = ''
    try:
        lenghts = [[] for _ in range(len(max(cols, key=len)))]
        for col in cols:
            for idx, value in enumerate(col):
                lenghts[idx].append(len(value))
        lengths = [max(lenght) for lenght in lenghts]

        # create formatting string with the length of the longest elements
        f = borderVertical + borderVertical.join(' {:>%d} ' % l for l in lengths) + borderVertical
        s = borderCross + borderCross.join(borderHorizontal * (l+2) for l in lengths) + borderCross
        string += s + '\n'
        print(s)
        for col in cols:
            string += f.format(*col) + '\n'
            print(f.format(*col))
            string += s + '\n'
            print(s)
    except ValueError:
        print("Value Error")
    finally:
        return string


def printTable_row(tbl, borderHorizontal = '-', borderVertical = '|', borderCross = '+'):
    cols = [list(x) for x in zip(*tbl)]
    lengths = [max(map(len, map(str, col))) for col in cols]
    f = borderVertical + borderVertical.join(' {:>%d} ' % l for l in lengths) + borderVertical
    s = borderCross + borderCross.join(borderHorizontal * (l+2) for l in lengths) + borderCross

    string = ''
    string += s + '\n'
    print(s)
    for row in tbl:
        string += f.format(*row) + '\n'
        print(f.format(*row))
        string += s + '\n'
        print(s)
    return string


info = {'attackers': {'68.183.65.178'},
        'victims': '10.10.2.140',
        'context': 'http GET 46.20.95.185'}

if __name__ == '__main__':
    collector(info, True)


"""
info = {'attackers': {'124.164.251.179',
                    '179.251.164.124.adsl-pool.sx.cn','46.246.64.46'},
        'victims': '10.10.2.140',
        'context': 'http GET 46.20.95.185'}
"""
