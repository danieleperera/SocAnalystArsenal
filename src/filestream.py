import json
import os
from __init__ import api
import requests
from tqdm import tqdm
from colorama import Fore, init

iconOK = (Fore.GREEN + '[!]')
iconNone = (Fore.YELLOW + '[!]')
init(autoreset=True)


# ===================== ************* ===============================
# ----------- using this for testing purposes -----------------------
# ===================== ************* ===============================
# info = {'attackers': '178.128.78.235\n167.99.81.228',
#           'victims': 'SOCUsers',
#           'context': 'dns bidr.trellian.com'}


def print_banner():
    banner = """
          _______
         /      /, 	;___________________;
        /      //  	; Soc-L1-Automation ;
       /______//	;-------------------;
      (______(/	            danieleperera
      """
    return banner


def get_api():
    # os platform indipendent
    APIpath = os.path.join(api, "api.json")
    with open(APIpath, "r") as f:
        contents = f.read()
        # print(contents)
        data = json.loads(contents)
        # print(data)
        return data


def progressbar_ip(ip_addresses):
    for i in tqdm(ip_addresses):
        pass

# ===================== ************* =================================
# ------- Get IP addresses information form api -----------------------
# ===================== ************* =================================


def ip_abuseipdb(ip: str) -> dict:
    """
    Documentation for ip_abuseipdb.
    It gets one ip addresse at a time as a string,
    uses request to do a get request to abuseip_db,
    gets json as text.

    param
        ip: str -- This is a string variable.

    example::

    ```
     ip = '124.164.251.179'
    ```

    return
    dict -- Returns json as a dict.

    """
    # --- abuseipdb data ----
    data = get_api()
    api = (data['API info']['abuseipdb']['api'])
    url = (data['API info']['abuseipdb']['url'])
    request_url = url.replace("API", api)
    colorIP = (Fore.RED + ip)
    print(iconOK + ' Checking Abuseipdb for ' + colorIP)

    final_url = request_url.replace("IP", ip)
    # --- Add Timeout for request ---
    try:
        info_json = requests.get(final_url, timeout=8)
        response = json.loads(info_json.text)
        return querry_status_abuseipdb(response)
    except requests.exceptions.Timeout:
        print(Fore.RED + 'Timeout error occurred for AbuseIPdb')
        return


def ip_urlscan(ip: str) -> dict:
    """
    Documentation for ip_urlscan.
    It gets one ip addresse at a time as a string,
    uses request to do a get request to ip_urlscan,
    gets json as text.

    param
        ip: str -- This is a string variable.

    example::

    ```
     ip = '124.164.251.179'
    ```

    return
    str -- Returns json as a string.

    """
    # --- urlscan.io ok----
    data = get_api()
    querry_ip = (data['API info']['urlscan.io']['querry_ip'])
    colorIP = (Fore.RED + ip)
    print(iconOK + ' Checking URLscan for ' + colorIP)

    requests_url = querry_ip+ip
    info_json = requests.get(requests_url)
    response = json.loads(info_json.text)
    return querry_status_urlscan_ip(response)


def ip_urlhaus(ip):
    # --- urlhaus data ok ----
    data = get_api()
    querry_host_url = (data['API info']['urlhaus']['querry_host_url'])
    colorIP = (Fore.RED + ip)
    print(iconOK + ' Checking URLhaus for ' + colorIP)

    params = {"host": ip}
    r = requests.post(querry_host_url, params)
    r.raise_for_status()
    # --- Returns a Dict -> check json infomation
    return querry_status_urlhause_ip(r.json())


def ip_virustotal(ip):

    # --- virustotal data ---
    data = get_api()
    colorIP = (Fore.RED + ip)
    api = (data['API info']['virustotal']['api'])
    print(iconOK + ' Checking virustotal for ' + colorIP)
    ip_address_url = (data['API info']['virustotal']['ip_address_url'])

    # https://developers.virustotal.com/v2.0/reference#comments-get

    params = {'apikey': api, 'ip': ip}
    response = requests.get(ip_address_url, params=params)
    response.raise_for_status()
    return querry_status_virustotal_ip(response.json())
    """
        for x in context:
        params = {'apikey': api, 'resource': x}
        response = requests.get(scan_url, params=params)
        print(response.json())
    """


# ================== ************* ===============================
# ------- Get Context information form api -----------------------
# ================= ************* =================================


def context_virustotal(context):
    # --- virustotal data ---
    data = get_api()
    colorContext = (Fore.RED + context)
    api = (data['API info']['virustotal']['api'])
    print(iconOK + ' Checking virustotal for ' + colorContext)
    context_url = (data['API info']['virustotal']['ip_address_url'])

    params = {'apikey': api, 'ip': context}
    response = requests.get(context_url, params=params)
    response.raise_for_status()

    return querry_status_virustotal_ip(response.json())


# ===================== ************* ===============================
# ------------------- CHECK JSON INFOMATION -----------------------
# ===================== ************* ===============================


def querry_status_urlhause_ip(positions):
    if positions['query_status'] != 'ok':
        print(iconNone + ' No result on URLhause')
    else:
        try:
            response_querry_url_information = {
                "urlhaus_reference": positions['urls'][0]['urlhaus_reference'],
                "threat": positions['urls'][0]['threat'],
                "url_status": positions['urls'][0]['url_status'],
                "tags": positions['urls'][0]['tags']}
            print(response_querry_url_information)
            return response_querry_url_information
        except KeyError:
            print("KeyError")


def querry_status_urlscan_ip(positions: dict) -> dict:
    """
    Documentation for querry_status_urlscan_ip.
    It gets a json a dictionary,
    it checks whether the dict is emtpy or not.
    If it's emtpy it prints no result on URLscan.
    Else it get's the longest group of dict which contains data.

    If a certain key isn't found i'll print key Error

    param
        positions: dict -- This is a dictionary variable.

    example::

    ```
     positions =     {
      "task": {
        "visibility": "public",
        "method": "api",
        "time": "2019-04-11T10:02:31.613Z",
        "source": "api",
        "url": "http://civ.pool.mn"
      },
      "stats": {
        "uniqIPs": 2,
        "consoleMsgs": 0,
        "dataLength": 54265,
        "encodedDataLength": 55104,
        "requests": 2
      },
      "page": {
        "country": "DE",
        "server": "Apache/2.4.7 (Ubuntu)",
        "city": "",
        "domain": "civ.pool.mn",
        "ip": "136.243.50.159",
        "asnname": "HETZNER-AS, DE",
        "asn": "AS24940",
        "url": "https://civ.pool.mn/",
        "ptr": "pool.mn"
      },
      "uniq_countries": 2,
      "_id": "336d51e3-e11c-4ed9-a687-dc4f3114f154",
      "result": "https://urlscan.io/api/v1/result/336d51e3-e11c-4ed9-a687-dc4f3114f154"
    }
    ```

    return
    dict -- Returns dict of values that i chose.

    """
    if positions['total'] == 0:
        print(iconNone + ' No result on URLscan')
        return False
    else:
        try:
            results = {"urlscan": positions['results'][0]['task']['url']}
            print(results)
            return results
        except KeyError:
            print("KeyError")


# --- Abuseipdb Category ---
category_abuseipdb = {
        "3": "Fraud Orders",
        "4": "DDoS Attack",
        "5": "FTP Brute-Force",
        "6": "Ping of Death",
        "7": "Phishing",
        "8": "Fraud VoIP",
        "9": "Open Proxy",
        "10": "Web Spam",
        "11": "Email Spam",
        "12": "Blog Spam",
        "13": "VPN IP",
        "14": "Port Scan",
        "15": "Hacking Generic",
        "16": "SQL Injection",
        "17": "Spoofing",
        "18": "Brute-Force",
        "19": "Bad Web Bot",
        "20": "Exploited Host",
        "21": "Web App Attack",
        "22": "SSH",
        "23": "IoT Targeted",

    }


def retruncategory(test_json):
    list = []
    for category in test_json:
        nice = (category_abuseipdb[str(category)])
        list.append(nice)
    return list


def querry_status_abuseipdb(positions: dict) -> dict:
    """
    Documentation for querry_status_abuseipdb.
    It gets a json a dictionary,
    it checks whether the dict is emtpy or not.
    If it's emtpy it prints no result on abuseipdb.
    Else it get's the longest group of dict which contains data.

    If a certain key isn't found i'll print key Error

    param
        positions: dict -- This is a dictionary variable.

    example::

    ```
     positions =     {  "ip": "51.75.143.169",
                        "category": [
                                        18,
                                        22
                                    ],
                        "created": "Thu, 11 Apr 2019 09:27:51 +0000",
                        "country": "France",
                        "isoCode": "FR",
                        "isWhitelisted": false,
                        "abuseConfidenceScore": 100}
    ```

    return
    dict -- Returns dict of values that i chose.

    """
    if positions == []:
        print(iconNone + ' No result on URLscan')
        return False
    else:
        try:
            result_with_correct_category = (max(positions, key=lambda x:
                                            (len(x['ip']),
                                                len(x['category'])))
                                            )
            data_from_abuseipdb = {
                "attacker": result_with_correct_category['ip'],
                "category":
                retruncategory(result_with_correct_category['category']),
                "country": result_with_correct_category['country'],
                "abuseConfidenceScore":
                result_with_correct_category['abuseConfidenceScore']}
            print(data_from_abuseipdb)
            return data_from_abuseipdb
        except KeyError:
            print("KeyError")


def querry_status_virustotal_ip(positions):
    if positions['response_code'] == -1:
        print('[!] No result on virustotal')
        return False
    else:
        try:
            simple_dict = {}
            for index, item in enumerate(
                    positions['detected_downloaded_samples']):
                simple_dict[f"detected_malicious_downloaded_samples_{index}_sha256"] = item['sha256']
                simple_dict[f"file_score_{index}"] = str(item['positives'])+'/'+str(item['total'])
            for index, item in enumerate(positions['detected_urls']):
                simple_dict[f"detected_urls_{index}"] = item['url']
                simple_dict[f"urls_score_{index}"] = str(item['positives'])+'/'+str(item['total'])
            # print(simple_dict)
            return simple_dict
        except KeyError:
            print("KeyError")
