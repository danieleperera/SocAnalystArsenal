# -*- coding: utf-8 -*-
# -*- style: PEP8 -*-
import json
import os
from __init__ import api
import requests
from tqdm import tqdm
from colorama import Fore, init
import json_parser
import time
import re
import __main__ as main

iconOK = (Fore.GREEN + '[ok]')
iconNone = (Fore.YELLOW + '[*]')
iconError = (Fore.RED + '[!]')
init(autoreset=True)


# ===================== ************* ===============================
# ----------- using this for testing purpose -----------------------
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
    for i in tqdm(ip_addresses, unit="data"):
        time.sleep(0.1)
        pass

# ===================== ************* =================================
# ------- Get IP addresses information form api -----------------------
# ===================== ************* =================================


def virustotal_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
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
    # --- API info ---
    data = get_api()
    api = (data['API info']['virustotal']['api'])
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'VirusTotal')
    print(iconNone + ' ' + colorString, end='')
    print(' checking WhoIs Information for ' + colorQuery)
    if sha_sum is None:
        if type == "domain":
            data = {"domain": query}  # The data to post
        elif type == "ip":
            query_ip = (data['API info']['virustotal']['query_ip'])
            params = {'apikey': api, 'ip': query}
            response = requests.get(query_ip, params=params)
        else:
            return

        if val:
            return response.json()
        else:
            return json_parser.parse_virustotal(response.json(), query)
    else:
        print(sha_sum)
        # --- virustotal data ---
        data = get_api()
        api = (data['API info']['virustotal']['api'])
        ip_address_url = (data['API info']['virustotal']['ip_address_url'])
        file_address_url = (data['API info']['virustotal']['file_url'])

        # https://developers.virustotal.com/v2.0/reference#comments-get

        params_ip = {'apikey': api, 'ip': query}
        params_file = {'apikey': api, 'resource': sha_sum}
        response_ip = requests.get(ip_address_url, params=params_ip)
        response_file = requests.get(file_address_url, params=params_file)

        if val:
            return response_ip.json(), response_file.json()
        else:
            return
    """
        for x in context:
        params = {'apikey': api, 'resource': x}
        response = requests.get(scan_url, params=params)
        print(response.json())
    """


def iphub_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    data = get_api()
    api = (data['API info']['iphub']['api'])
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'IPhub')
    print(iconNone + ' ' + colorString, end='')
    print(' checking proxy or spoofed ' + colorQuery)
    if type == "domain":
        print(Fore.RED + '[x] IPhub does not check domains')
    elif type == "ip":
        query_ip = data['API info']['iphub']['query_ip']
        url = query_ip+query
        headers = {
                    'X-Key': api}
        response = requests.get(url, headers=headers)

        if val:
            return response.json()
        else:
            return json_parser.parse_iphub(response.json(), query)


def getipintel_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    data = get_api()
    email = data['API info']['getipintel']['email']
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'GetIPintel')
    print(iconNone + ' ' + colorString, end='')
    print(' checking Proxy VPN Tor ' + colorQuery)
    if type == "domain":
        print(Fore.RED + '[x] GetIPintel does not check domains')
    elif type == "ip":
        query_ip = data['API info']['getipintel']['query_ip']
        url = query_ip.format(query, email)
        response = requests.get(url)

        if val:
            return response.json()
        else:
            return json_parser.parse_getipintel(response.json(), query)


"""
def fofa_query(query: str, type: str, val: bool, sha_sum: list = None) -> dict:
    data = get_api()
    email = data['API info']['fofa']['email']
    api_key = data['API info']['fofa']['api']
    colorQuery = (Fore.RED + query)
    print(iconNone, end='')
    print(' Checking fofa for ' + colorQuery)
    b64query = base64.b64encode(query)
    print(b64query)
    if type == "domain" or type == "ip":
        query_all = data['API info']['fofa']['query_all']
        params = {
            'email': email,
            'key': api_key,
            'qbase64': b64query
        }

        response = requests.get(query_all, params=params)

        if val:
            return response.json()
        else:
            pass

"""


def threatminer_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    data = get_api()

    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Threatminer')
    print(iconNone + ' ' + colorString, end='')
    print(' checking further information ' + colorQuery)

    if type == "domain":
        pass
    elif type == "ip":
        query_ip = data['API info']['threatminer']['query_ip']
        url = query_ip.format(query)
        response = requests.get(url)

        if val:
            return response.json()
        else:
            return json_parser.parse_threatminer(response.json(), query)


def threatcrowd_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    data = get_api()

    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Threatcrowd')
    print(iconNone + ' ' + colorString, end='')
    print(' checking current status' + colorQuery)

    if type == "domain":
        pass
    elif type == "ip":
        query_all = data['API info']['threatcrowd']['query_ip']
        params = {
            'ip': query,
        }

        response = requests.get(query_all, params=params)

    if val:
        return response.json()
    else:
        return json_parser.parse_threatcrowd(response.json(), query)


def abuseipdb_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
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
    data = get_api()
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Abuseipdb')
    print(iconNone + ' ' + colorString, end='')
    print(' checking blacklisted ' + colorQuery)
    if type == "domain":
        print(Fore.RED + '[x] AbuseIPdb does not check domains')
    elif type == "ip":
        # --- abuseipdb data ----
        api = (data['API info']['abuseipdb']['api'])
        url = (data['API info']['abuseipdb']['url'])
        request_url = url.replace("API", api)
        final_url = request_url.replace("IP", query)
        # --- Add Timeout for request ---
    else:
        pass
    try:
        response = requests.get(final_url, timeout=10)
        if val:
            return response.json()  # this returns only huge dict
        else:
            return json_parser.parse_abuseipdb(response.json(), query)
    except requests.exceptions.Timeout:
        print(Fore.RED + 'Timeout error occurred for AbuseIPdb')
        return


def urlscan_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
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
    data = get_api()
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'URLscan')
    print(iconNone + ' ' + colorString, end='')
    print(' checking further information ' + colorQuery)
    if type == "domain":
        query_domain = data['API info']['urlscan.io']['query_domain']
        requests_url = query_domain+query
        info_json = requests.get(requests_url)
        response = json.loads(info_json.text)
    elif type == "ip":
        # --- urlscan.io ok----
        query_ip = data['API info']['urlscan.io']['query_ip']
        requests_url = query_ip+query
        response = requests.get(requests_url)

    if val:
        return response.json()
    else:
        return json_parser.parse_urlscan(response.json(), query)


def urlhause_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
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
    data = get_api()
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'UrlHause')
    print(iconNone + ' ' + colorString, end='')
    print(
        ' checking IP address/Domain was used to spread malware '
        + colorQuery)
    if type == "domain" or type == "ip":
        # --- urlhaus data ok ----
        querry_host_url = (data['API info']['urlhaus']['querry_host_url'])
        params = {"host": query}
        response = requests.post(querry_host_url, params)
    elif type == "url":
        data = {"host": query}
    else:
        pass
    if val:
        return response.json()
    else:
        return json_parser.parse_urlhause(response.json(), query)


def domain_virustotal(
        domain: str,
        boolvalue: bool,
        sha_sum: list = None) -> dict:
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
        api = (
            data['API info']['virustotal']['api'])
        domain_address_url = (
            data['API info']['virustotal']['domain_address_url'])

        # https://developers.virustotal.com/v2.0/reference#comments-get

        params = {'apikey': api, 'domain': domain}
        response_domain = requests.get(domain_address_url, params=params)
        if boolvalue:
            return response_domain.json(), response_domain.json()
        else:
            return None
            # querry_status_virustotal_domain(response_domain.json(), domain)
    else:
        print(sha_sum)
        # --- virustotal data ---
        data = get_api()
        api = (data['API info']['virustotal']['api'])
        ip_address_url = (data['API info']['virustotal']['ip_address_url'])
        domain_address_url = (
            data['API info']['virustotal']['domain_address_url'])

        # https://developers.virustotal.com/v2.0/reference#comments-get

        params_domain = {'apikey': api, 'domain': domain}
        params_file = {'apikey': api, 'resource': sha_sum}
        response_domain = requests.get(ip_address_url, params=params_domain)
        response_file = requests.get(domain_address_url, params=params_file)

        if boolvalue:
            return domain_address_url.json(), response_file.json()
        else:
            return None
            # querry_status_virustotal_domain(
            # domain_address_url.json(), domain),
            # querry_status_virustotal_file(response_file.json())
    """
        for x in context:
        params = {'apikey': api, 'resource': x}
        response = requests.get(scan_url, params=params)
        print(response.json())
    """


def shodan_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    # --- API info ---
    data = get_api()
    api_key = data['API info']['shodan']['api']
    # print
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Shodan')
    print(iconNone + ' ' + colorString, end='')
    print(
        ' Checking information about host and see if it was compromised '
        + colorQuery)
    if type == "domain":
        data = {"domain": query}  # The data to post
    elif type == "ip":
        url = data['API info']['shodan']['query_ip'].format(
            query,
            api_key)
        response = requests.get(url)
    else:
        return

    if val:
        return response.json()
    else:
        return json_parser.parse_shodan(response.json(), query)


def apility_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    # --- API info ---
    data = get_api()
    api_key = data['API info']['apility']['api']
    # print
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Apility')
    print(iconNone + ' ' + colorString, end='')
    print(' checking reputation and activity through time ' + colorQuery)
    if type == "domain":
        data = {"domain": query}  # The data to post
    elif type == "ip":
        get_url_ip = data['API info']['apility']['url_ip_request']
        headers = {'Accept': 'application/json', 'X-Auth-Token': api_key}
        url = get_url_ip+query
        response = requests.get(url, headers=headers)
    try:
        if val:
            return response.json()
        else:
            return json_parser.parse_apility(response.json(), query)
    except json.decoder.JSONDecodeError:
        pass


def hybrid_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    # --- API info ---
    data = get_api()
    api_key = data['API info']['hybrid']['api']
    # printing name
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Hybrid')
    print(iconNone + ' ' + colorString, end='')
    print(' checking association with malware ' + colorQuery)

    if type == "domain":
        data = {"domain": query}  # The data to post
    elif type == "ip":
        url = "https://www.hybrid-analysis.com/api/v2/search/terms"
        # The api url
        headers = {
            "api-key": api_key,
            "user-agent": "Falcon Sandbox",
            "accept": "application/json"}
        # The request headers
        data = {"host": query}
        response = requests.post(url, headers=headers, data=data)
    else:
        pass
    if val:
        return response.json()
    else:
        return json_parser.parse_hybrid(response.json(), query)

# ===================== ************* ===============================
# -----------Working and testing from here on -----------------------
# ===================== ************* ===============================
# http://check.getipintel.net/check.php?ip=66.228.119.72&contact=mr.px0r@gmail.com&format=json


# ip ='68.183.65.178'

# ip = '188.40.75.132'
"""
# print(fofa_query(ip, 'ip', True))

test = virustotal_query(ip, 'ip', False)
#progressbar_ip(ip)
print(test)

test1 = iphub_query(ip, 'ip', False)
#progressbar_ip(ip)
print(test1)

test2 = getipintel_query(ip, 'ip', False)
progressbar_ip(ip)
print(test2)

test3 = shodan_query(ip, 'ip', False)
progressbar_ip(ip)
print(test3)

test4 = threatcrowd_query(ip, 'ip', False)
#progressbar_ip(ip)
print(test4)

test5 = hybrid_query(ip, 'ip', False)
#progressbar_ip(ip)
print(test5)

test6 = apility_query(ip, 'ip', False)
#progressbar_ip(ip)
print(test6)

test7 = abuseipdb_query(ip, 'ip', False)
#progressbar_ip(ip)
print(test7)

test8 = urlscan_query(ip, 'ip', False)
#progressbar_ip(ip)
print(test8)

test9 = urlhause_query(ip, 'domain', False)
#progressbar_ip(ip)
print(test9)

test10 = threatminer_query(ip, 'domain', True)
#progressbar_ip(ip)
print(test10)
"""
# table_reputation = printTable_row(test5)
# table_reputation = printTable_row(test6)

# ===================== ************* ===============================
# ---------- Various Checks and printing ticket --------------------
# ===================== ************* ===============================


def get_ip(ip: dict) -> str:
    """
    Documentation for get_ip.
    It uses a dictionary and check whether,
    the key attackers is empty or not.
    If it's empty then prints No attacker ip found,
    else returns a ip address as string.

    param
        ip: dict -- This is a dictionary variable.

    example::

    ```
     ip[attackers] = {'124.164.251.179',
                      '179.251.164.124.adsl-pool.sx.cn'},
    ```

    return
    str -- Returns only ip addresses as a string.

    """
    if ip['attackers'] == "":
        print("No attacker ip found...")
    else:
        # print(ip['attackers'])
        return ip['attackers']


def text_header(head):
    test = '''### Attackers ->{}
### Victims   ->{}
### Context   ->{}\n'''.format(
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


def check_ip(ipv4_address):
    test = []
    for i in ipv4_address.split(","):
        # print(i)
        regex_ipv4_public = (r"""^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$)$""")
        matches_public = re.finditer(regex_ipv4_public, i, re.MULTILINE)

        for x in matches_public:
            test.append(("{match}".format(match=x.group())))
    return test


def manual_mode_ip(ip_addr: list, verbosity: bool, sha_sum: list = None):
    # check if argpase values are null
    if ip_addr is None:
        ip = ''
        while True:
            print(iconNone, end='')
            ip = input(' Insert a list of potential malicious ip addresses:')
            datalist = ip.split(",")
            if check_ip(ip) == []:
                print(iconError, end='')
                print(" Not valid ip address have been insert, please re-try")
                continue
            else:
                break
        ip_addr = [item.replace(' ', '') for item in datalist]
        simple_dict = {'attackers': ip_addr}
        main.collector(simple_dict, verbosity)
    else:
        # --- Complete manual mode ---
        ip_addr = [item.replace(' ', '') for item in ip_addr]
        simple_dict = {'attackers': ip_addr}
        if sha_sum == []:
            return main.collector(simple_dict, verbosity)
        else:
            return main.collector(simple_dict, verbosity, sha_sum)


def verbose_mode(verbosity: bool) -> bool:
    if verbosity:
        # print("Flag non c'è")   verbosity minima
        return False
    else:
        # print("Flag c'è")   verbosity massima
        return True


def printTable(tbl, borderHorizontal='-', borderVertical='|', borderCross='+'):
    string = ''
    try:
        # get the columns split by the values
        cols = [col.split(', ') for col in tbl]

        # find the longests strings
        lenghts = [[] for _ in range(len(max(cols, key=len)))]
        for col in cols:
            for idx, value in enumerate(col):
                lenghts[idx].append(len(value))
        lengths = [max(lenght) for lenght in lenghts]

        # create formatting string with the length of the longest elements
        f = borderVertical + borderVertical.join(
            ' {:>%d} ' % l for l in lengths) + borderVertical
        s = borderCross + borderCross.join(
            borderHorizontal * (l+2) for l in lengths) + borderCross
        string += s + '\n'
        # print(s)
        for col in cols:
            string += f.format(*col) + '\n'
            # print(f.format(*col))
            string += s + '\n'
            # print(s)
        return string
    except ValueError:
        pass
    finally:
        return


def printTable_row(
        tbl,
        borderHorizontal='-',
        borderVertical='|',
        borderCross='+'):
    string = ''
    try:
        cols = [list(x) for x in zip(*tbl)]
        lengths = [max(map(len, map(str, col))) for col in cols]
        f = borderVertical + borderVertical.join(
            ' {:>%d} ' % l for l in lengths) + borderVertical
        s = borderCross + borderCross.join(
            borderHorizontal * (l+2) for l in lengths) + borderCross
        string += s + '\n'
        # print(s)
        for row in tbl:
            string += f.format(*row) + '\n'
            # print(f.format(*row))
            string += s + '\n'
            # print(s)
        return string
    except TypeError:
        pass


def check_domain_or_ip(data: list) -> str:
    ip = []
    for i in data:
        regex_ipv4_public = (r"""^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$)$""")
        matches_public = re.finditer(regex_ipv4_public, i, re.MULTILINE)
        for x in matches_public:
            ip.append(("{match}".format(match=x.group())))

    yield ip, 'ip'
    domain = []
    for z in data:
        # print(z)
        regex_domain = r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
        matches_domain = re.finditer(regex_domain, z, re.MULTILINE)
        for f in matches_domain:
            domain.append(("{match}".format(match=f.group())))
    # print(domain)
    yield domain, 'domain'
