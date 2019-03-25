import json
import os
from __init__ import api
import webscapper
import requests
import category_abuseipdb

# ------- Get info about attacker, victim, context from the webscapper -----
# info = webscapper.get_info()


# ------- using this for testing purposes -----
#info = {'Attackers': '178.128.78.235\n167.99.81.228', 'Victims': 'SOCUsers', 'Context': 'dns bidr.trellian.com'}
info = {'Attackers': '127.0.0.1\n127.0.0.1', 'Victims': 'SOCUsers', 'Context': 'dns bidr.trellian.com'}
print(info)


def num_of_attack_ip():
    # --- check and get attacker ip ---
    if info['Attackers'] == "":
        print("No attacker ip found...")
    else:
        return(info['Attackers'])


def num_of_attack_context():
    # --- Attack Context ---
    if info['Context'] == "":
        print("No context found...")
    else:
        return(info['Context'])


def get_api():
    # os platform indipendent
    APIpath = os.path.join(api, "api.json") 
    with open(APIpath, "r") as f:
        contents = f.read()
        # print(contents)
        data = json.loads(contents)
        #print(data)
        return(data)


def data_abuseipdb():
    # --- abuseipdb data ----
    data = get_api()
    api = (data['API info']['abuseipdb']['api'])
    url = (data['API info']['abuseipdb']['url'])
    request_url = url.replace("API", api)

    # --- check and get attacker ip ---
    ip = num_of_attack_ip().split("\n")
    # --- check and get attacker ip ---
    for i in ip:
        final_url = request_url.replace("IP", i)
        print(final_url)
        info_json = requests.get(final_url)
        response = json.loads(info_json.text)
        bestresult = (max(response, key=lambda x: (len(x['ip']), len(x['category']))))

        #print(bestresult)
        #print(category_abuseipdb.retruncategory(bestresult['category']))
        #return(bestresult['ip'], category_abuseipdb.retruncategory(bestresult['category']), bestresult['country'], bestresult['abuseConfidenceScore'])

        print("""\t\tIP attacker: {}
            \tCategory: {}
            \tCountry: {}
            \tAbuseConfidenceScore: {}%""".format(bestresult['ip'], category_abuseipdb.retruncategory(bestresult['category']),bestresult['country'],bestresult['abuseConfidenceScore']))


def data_urlscan():
    # --- urlscan.io data ----
    data = get_api()
    api = (data['API info']['urlscan.io']['api'])
    url = (data['API info']['urlscan.io']['url'])
    #request_url = url.replace("domain:", api)
    #print(request_url)

    context = num_of_attack_context().split(" ")[1:]
    for i in context:
        requests_url = url+i
        print(requests_url)
        info_json = requests.get(requests_url)
        response = json.loads(info_json.text)
        print(response['results'][0]['page'])
        """
        {'country': 'AU', 'server': 'Apache/2.4.10 (Debian)', 'city': '', 'domain': 'www.trellian.com', 'ip': '103.224.182.21', 'asnname': 'TRELLIAN-AS-AP Trellian Pty. Limited, AU', 'asn': 'AS133618', 'url': 'https://www.trellian.com/dsn/index.html', 'ptr': 'www.trellian.com'}
        """
        #return(response['results'][0]['page'])


def data_urlhaus():
    # --- urlhaus data ----
    data = get_api()
    #api = (data['API info']['abuseipdb']['api'])
    url = (data['API info']['urlhaus']['url'])
    # --- Attack Context ---
    context = num_of_attack_context().split(" ")[1:]
    for i in context:
        print(i)
        r = requests.post(url, data={"url": "http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/"})
        r.raise_for_status()
        print(r.text)
    
    # --- check and get attacker ip ---
    ip = num_of_attack_ip().split("\n")
    # --- check and get attacker ip ---
        
    for i in ip:
        print(i)
        r = requests.post(url, data={"url": i})
        r.raise_for_status()
        print(r.text)


def data_virustotal():
    # --- virustotal data ---
    data = get_api()
    api = (data['API info']['virustotal']['api'])

    file_url = (data['API info']['virustotal']['file_url'])
    ip_address_url = (data['API info']['virustotal']['ip_address_url'])
    scan_url = (data['API info']['virustotal']['scan_url'])
    comments_url = (data['API info']['virustotal']['comments_url'])

    #https://developers.virustotal.com/v2.0/reference#comments-get






data_abuseipdb()
#data_urlscan()
#data_urlhaus()
#data_virustotal()