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


def ip_abuseipdb(ip: str, boolvalue: bool, sha_sum: list = None) -> dict:
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
        if boolvalue:
            return response
        else:
            return querry_status_abuseipdb(response)
    except requests.exceptions.Timeout:
        print(Fore.RED + 'Timeout error occurred for AbuseIPdb')
        return


def ip_urlscan(ip: str, boolvalue: bool, sha_sum: list = None) -> dict:
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
    dict -- Returns json as a dict.

    """
    # --- urlscan.io ok----
    data = get_api()
    querry_ip = (data['API info']['urlscan.io']['url'])
    colorIP = (Fore.RED + ip)
    print(iconOK + ' Checking URLscan for ' + colorIP)

    requests_url = querry_ip+ip
    info_json = requests.get(requests_url)
    response = json.loads(info_json.text)
    if boolvalue:
        return response
    else:
        return querry_status_urlscan_ip(response)


def ip_urlhaus(ip: str, boolvalue: bool, sha_sum: list = None) -> dict:
    """
    Documentation for ip_urlhaus.
    It gets one ip addresse at a time as a string,
    uses request to do a get request to ip_urlhaus,
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
    # --- urlhaus data ok ----
    data = get_api()
    querry_host_url = (data['API info']['urlhaus']['querry_host_url'])
    colorIP = (Fore.RED + ip)
    print(iconOK + ' Checking URLhaus for ' + colorIP)

    params = {"host": ip}
    r = requests.post(querry_host_url, params)
    r.raise_for_status()

    if boolvalue:
        return r.json()
    else:
        return querry_status_urlhause_ip(r.json())


def ip_virustotal(ip: str, boolvalue: bool, sha_sum: list = None) -> dict:
    """
    Documentation for ip_urlhaus.
    It gets one ip addresse at a time as a string,
    uses request to do a get request to ip_urlhaus,
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
    if sha_sum is None:
        # --- virustotal data ---
        data = get_api()
        colorIP = (Fore.RED + ip)
        api = (data['API info']['virustotal']['api'])
        print(iconOK + ' Checking virustotal for ' + colorIP)
        ip_address_url = (data['API info']['virustotal']['ip_address_url'])

        # https://developers.virustotal.com/v2.0/reference#comments-get

        params = {'apikey': api, 'ip': ip}
        response_ip = requests.get(ip_address_url, params=params)
        if boolvalue:
            return response_ip.json()
        else:
            return querry_status_virustotal_ip(response_ip.json(), ip)
    else:
        print(sha_sum)
        # --- virustotal data ---
        data = get_api()
        colorIP = (Fore.RED + ip)
        api = (data['API info']['virustotal']['api'])
        print(iconOK + ' Checking virustotal for ' + colorIP)
        ip_address_url = (data['API info']['virustotal']['ip_address_url'])
        file_address_url = (data['API info']['virustotal']['file_url'])

        # https://developers.virustotal.com/v2.0/reference#comments-get

        params_ip = {'apikey': api, 'ip': ip}
        params_file = {'apikey': api, 'resource': sha_sum}
        response_ip = requests.get(ip_address_url, params=params_ip)
        response_file = requests.get(file_address_url, params=params_file)

        if boolvalue:
            return response_ip.json(), response_file.json()
        else:
            return querry_status_virustotal_ip(response_ip.json(), ip), querry_status_virustotal_file(response_file.json())
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


def querry_status_urlhause_ip(positions: dict) -> dict:
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
     positions = {
                    "query_status": "ok",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/host/187.107.132.33/",
                    "host": "187.107.132.33",
                    "firstseen": "2019-04-11 10:06:01 UTC",
                    "url_count": "1",
                    "blacklists": {
                        "spamhaus_dbl": "unknown_return_code",
                        "surbl": "not listed"},
                    "urls": [{
                        "id": "175438",
                        "urlhaus_reference": "https://urlhaus.abuse.ch/url/175438/",
                        "url": "http://187.107.132.33:19623/.i",
                        "url_status": "online",
                        "date_added": "2019-04-11 10:06:10 UTC",
                        "threat": "malware_download",
                        "reporter": "zbetcheckin",
                        "larted": "true",
                        "takedown_time_seconds": "",
                    "tags": [
                        "elf",
                        "hajime"]}]
                    }
    ```

    return
    dict -- Returns dict of values that i chose.

    """
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
            result_with_correct_category = (max(positions, key=lambda x:(len(x['ip']),len(x['category']))))
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
        except TypeError:
            print("TypeError")


def querry_status_virustotal_ip(positions: dict, ip_address_to_view: str) -> dict:
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
     positions = {
                    "whois":   "domain: virtua.com.br
                                server: dns1.virtua.com.br 201.6.4.15
                                server: dns2.virtua.com.br 201.6.4.61
                                server: dns3.virtua.com.br 189.6.48.3
                                created: 19980904 #115278
                                changed: 20190103
                                expires: 20210904
                                status: published
                                nic-hdl-br: GRSVI
                                created: 20080512
                                changed: 20090518
                                nic-hdl-br: ANPSI74
                                created: 20090429
                                changed: 20170427
                                nic-hdl-br: CLV199
                                created: 20060321
                                changed: 20170616% cert.br,
                                http://www.cert.br/,
                                respectivelly to [REDACTED]@cert.br",
                    "whois_timestamp": 1554983890,
                    "detected_downloaded_samples": [
                    {
                        "date": "2019-04-11 10:05:39",
                        "positives": 32,
                        "total": 55,
                        "sha256":
                            "a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3"
                    }],
                    "response_code": 1,
                    "as_owner": "CLARO S.A.",
                    "verbose_msg": "IP address in dataset",
                    "country": "BR",
                    "resolutions": [],
                    "detected_urls": [],
                    "continent": "SA",
                    "asn": 28573,
                    "network": "187.107.128.0/17"}
    ```

    return
    dict -- Returns dict of values that i chose.

    """
    if positions['response_code'] == -1:
        print('[!] No result on virustotal')
        return False
    else:
        try:
            simple_dict = {}
            for index, item in enumerate(
                    positions['detected_downloaded_samples']):
                simple_dict["Detected samples "] = ('for this ip address : {}'.format(ip_address_to_view))
                simple_dict[f"detected samples_{index}"] = item['sha256']
                #simple_dict[f"file_score_{index}"] = str(item['positives'])+'/'+str(item['total'])
            for index, item in enumerate(positions['detected_urls']):
                simple_dict[f"detected_urls_{index}"] = item['url']
                #simple_dict[f"urls_score_{index}"] = str(item['positives'])+'/'+str(item['total'])
            # print(simple_dict)
            return simple_dict
        except KeyError:
            print("KeyError")


def querry_status_virustotal_file(resp_json):
    if resp_json['response_code'] == 0:
        print('[!] Invalid sha')
        return False
    else:
        detected_dict = {}
        for index, av_name in enumerate(resp_json['scans']):
        # For each Anti-virus name, find the detected value.
            detected = resp_json['scans'][av_name]['detected']
            # if the above value is true.
            detected_dict["found_positives"] = ("{} / {}".format(resp_json['positives'], resp_json['total']))
            #detected_dict["permalink"] = resp_json["permalink"]
            if detected is True:
                # Print Engines which detect malware.
                # print(f'{av_name} detected Malware!')
                # Add detected engine name and it's result to the detected_dict.
                detected_dict[av_name] = resp_json['scans'][av_name]['result']
    #print(detected_dict)
    return detected_dict
