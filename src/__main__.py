import filestream
import os
import tempfile
import pyperclip
from win10toast import ToastNotifier
from __init__ import SRC
import re
from colorama import Fore


def check_webscapper():
    Webscapperpath = os.path.join(SRC, "webscapper.py")
    print(Fore.CYAN + filestream.print_banner())
    exists = os.path.isfile(Webscapperpath)
    if exists:
        print(Webscapperpath)
        import webscapper
        main(webscapper.get_info())
        # Testing purposes
        #info = {'attackers': {'124.164.251.179', '179.251.164.124.adsl-pool.sx.cn'}, 'victims': '10.10.2.140', 'context': 'http GET 46.20.95.185'}
        #main(info)
    else:
        print("Il tool automatizzato per cercare gli ip malevoli non esiste, inserisci manualmente gli ip")
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--ip", dest="ip", help="somehelp bla bla", default="")
        addr = parser.parse_args()
        if addr.ip == '':
            ip = ''
            while True:
                ip = input('Please input ip: ')
                
                if check_ip(ip) == []:
                    continue
                else:
                    break
            print(ip)
            # --- Creating a set ---
            ips = ip.split(",")
            ipss = set(ips)
            # --- End set variable ---
            attackers = {}
            attackers['attackers'] = ipss
            print(attackers)
            main(attackers)
        else:
            print(type(addr.ip))
            attackers = {}
            # --- Creating a set ---
            ips = addr.ip.split(",")
            ipss = set(ips)
            # --- End set variable ---
            attackers['attackers'] = ipss
            print(type(attackers))
            print(attackers)
            main(attackers)        


def main(info):
    #info = {'attackers': {'124.164.251.179', '179.251.164.124.adsl-pool.sx.cn'}, 'victims': '10.10.2.140', 'context': 'http GET 46.20.95.185'}
    # ------- Get info about attacker, victim, context from the webscapper -----
    

    # --- Notification ---
    toaster = ToastNotifier()
    # --- * ---

    # --- Clipboard / tmp file ---
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'r+') as tmp:
            ip_addresses = get_ip(info)
            #tmp.write(text_header(info))
            for ip in ip_addresses:
                # --- URLscan ---
                urlscan = filestream.data_urlscan(ip)
                filestream.progressbar_ip(ip_addresses)
                #tmp.write(str(text_body(urlscan)))
                for i in text_body(urlscan):
                    tmp.write(i)
                # --- URLscan end ---
                
                # --- URLhaus ---
                urlhaus = filestream.data_urlhaus(ip)
                filestream.progressbar_ip(ip_addresses)
                #tmp.write(str(text_body(urlhaus)))
                for i in text_body(urlhaus):
                    tmp.write(i)
                # --- URLhaus end ---
                
                # --- AbuseIPdb ---
                abuseipdb = filestream.data_abuseipdb(ip)
                filestream.progressbar_ip(ip_addresses)
                #tmp.write(str(text_body(abuseipdb)))
                for i in text_body(abuseipdb):
                    tmp.write(i)
                # --- AbuseIPdb end ---
                
                # --- virustotal ---
                virustotal = filestream.data_virustotal(ip)
                filestream.progressbar_ip(ip_addresses)
                #tmp.write(str(virustotal))
                for i in text_body(virustotal):
                    tmp.write(i)
                # --- virustotal end---
            """
            multiple_context = get_context(info).split(" ")[1:]
            for context in tqdm(multiple_context):
                #print(context)
                pass
            """

            tmp.seek(0)
            content = tmp.read()
            if content == '':
                print('\n\nNo Ticket was copied to clipboard')
            else:
                pyperclip.copy(content)
                toaster.show_toast("Notifica", "il ticket è stato copiato nella clipboard", duration=10)
    finally:
        # print(path)
        os.remove(path)
        


def get_ip(ip):
    if ip['attackers'] == "":
        print("No attacker ip found...")
    else:
        print(ip['attackers'])
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


if __name__ == '__main__':
    check_webscapper()
    #main()
    #print(check_ip())