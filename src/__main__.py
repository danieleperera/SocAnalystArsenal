import filestream
import os
import tempfile
import pyperclip
from win10toast import ToastNotifier
#import webscapper


def main():
    info = {'attackers': '178.128.78.235', 'victims': 'SOCUsers', 'context': 'dns http://www.abcdefg.mn'}
    # ------- Get info about attacker, victim, context from the webscapper -----
    #info = webscapper.get_info()
    

    # --- Notification ---
    toaster = ToastNotifier()
    # --- * ---

    # --- Clipboard / tmp file ---
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'r+') as tmp:
            ip_addresses = get_ip(info).split("\n")
            tmp.write(text_header(info))
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
            pyperclip.copy(content)
    finally:
        # print(path)
        os.remove(path)
        toaster.show_toast("Notifica", "il ticket è stato copiato nella clipboard", duration=10)


def get_ip(ip):
    if ip['attackers'] == "":
        print("No attacker ip found...")
    else:
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


if __name__ == '__main__':
    main()