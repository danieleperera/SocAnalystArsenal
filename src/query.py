# -*- coding: utf-8 -*-
# -*- style: PEP8 ✔ ✘ -*-
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
import tempfile
import pyperclip
from typing import List, Union
import socket
import threading
iconOK = (Fore.GREEN + '[ok]')
iconNone = (Fore.YELLOW + '[*]')
iconError = (Fore.RED + '[!]')
init(autoreset=True)
fd_default, path_default = tempfile.mkstemp()

# ===================== ************* ===============================
# ----------- using this for testing purpose -----------------------
# ===================== ************* ===============================
# info = {'attackers': '178.128.78.235\n167.99.81.228',
#           'victims': 'SOCUsers',
#           'context': 'dns bidr.trellian.com'}


def print_banner():
    banner = """
          _______
         /      /, 	;_____________________;
        /      //  	; soc-analyst-arsenal ;
       /______//	;---------------------;
      (______(/	              danieleperera
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
        query_type: str,
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
    # --- Header data ---
    header_whois = (
        '\nWhois Information ' + query)
    # --- API info ---
    data = get_api()
    api = (data['API info']['virustotal']['api'])
    # --- Color printing ---
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'VirusTotal')
    # --- Status ---
    print(iconNone + ' ' + colorString, end='')
    print(' checking WhoIs Information for ' + colorQuery)
    # --- Check query type ---
    if query_type == "domain":
        query_domain = data['API info']['virustotal']['query_domain']
        params = {'apikey': api, 'domain': query}
        response = requests.get(query_domain, params=params)
    elif query_type == "ip":
        query_ip = (data['API info']['virustotal']['query_ip'])
        params = {'apikey': api, 'ip': query}
        response = requests.get(query_ip, params=params)
    elif query_type == 'sha':
        query_sha = (data['API info']['virustotal']['file_url'])
        params = {'apikey': api, 'resource': query}
        response = requests.get(query_sha, params=params)
    else:
        return

    jdata = response.json()

    if jdata['response_code'] == 0:
        Nodata = 'No data found on virustotal'
        create_tmp_to_clipboard(
            Nodata,
            header_whois,
            val,
            None)
    else:
        if val:
            return create_tmp_to_clipboard(
                jdata,
                header_whois,
                val,
                None)
        else:
            for i in json_parser.parse_virustotal(response.json(), query):
                if type(i) is dict:
                    create_tmp_to_clipboard(
                        i,
                        header_whois,
                        val,
                        'normal')
                elif type(i) is list:
                    header = "associated hash file for {}".format(query)
                    create_tmp_to_clipboard(
                        i,
                        header,
                        val,
                        'print_row_table')


def iphub_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    header_spoofed_IPhub = (
        'VPN/Proxy/Tor Information IPhub '
        + query)
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
            return create_tmp_to_clipboard(
                response.json(),
                header_spoofed_IPhub,
                val,
                None)
        else:
            return create_tmp_to_clipboard(
                json_parser.parse_iphub(response.json(), query),
                header_spoofed_IPhub,
                val,
                'normal')


def getipintel_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    header_spoofed_getipintel = (
        'VPN/Proxy/Tor Information GetIPintel '
        + query)
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
            return create_tmp_to_clipboard(
                response.json(),
                header_spoofed_getipintel,
                val,
                None)
        else:
            return create_tmp_to_clipboard(
                json_parser.parse_getipintel(response.json(), query),
                header_spoofed_getipintel,
                val,
                'normal')


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
    header_info2 = (
        'Report tagging information/IOCs '
        + query + '\n')

    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Threatminer')
    print(iconNone + ' ' + colorString, end='')
    print(' Report tagging information/IOCs information ' + colorQuery)

    if type == "domain":
        pass
    elif type == "ip":
        query_ip = data['API info']['threatminer']['query_ip']
        url = query_ip.format(query)
        response = requests.get(url)
        data_json = response.json()
        if data_json['status_code'] == '200':
            if val:
                return create_tmp_to_clipboard(
                    response.json(),
                    header_info2,
                    val,
                    None)
            else:
                return create_tmp_to_clipboard(
                    json_parser.parse_threatminer(response.json(), query),
                    header_info2,
                    val,
                    'normal')
        else:
            pass


def threatcrowd_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    data = get_api()
    header_status = (
        'Current status information '
        + query)
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Threatcrowd')
    print(iconNone + ' ' + colorString, end='')
    print(' checking current status ' + colorQuery)

    if type == "domain":
        pass
    elif type == "ip":
        query_all = data['API info']['threatcrowd']['query_ip']
        params = {
            'ip': query,
        }

        response = requests.get(query_all, params=params)
    jdata = response.json()
    #print(jdata)
    if jdata['response_code'] == '0':
        pass
    else:
        if val:
            return create_tmp_to_clipboard(
                jdata,
                header_status,
                val,
                None)
        else:
            return create_tmp_to_clipboard(
                    json_parser.parse_threatcrowd(jdata, query),
                    header_status,
                    val,
                    'normal')


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
    header_blacklisted = (
        'Blacklisted Data '
        + query)
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
        jdata = response.json()
        if jdata == []:
            #print("no data")
            pass
        else:
            if val:
                return create_tmp_to_clipboard(
                    response.json(),
                    header_blacklisted,
                    val,
                    None)
            else:
                status, parsed_Data = json_parser.parse_abuseipdb(
                    response.json(),
                    query)
            if status == 'ok':
                return create_tmp_to_clipboard(
                    parsed_Data,
                    header_blacklisted,
                    val,
                    'normal')
            elif status == 'KeyError':
                return create_tmp_to_clipboard(
                    parsed_Data,
                    header_blacklisted,
                    val,
                    None)     
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
    header_info = (
        'Suspicious connections '
        + query)
    data = get_api()
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'URLscan')
    print(iconNone + ' ' + colorString, end='')
    print(' Suspicious connections ' + colorQuery)
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

    jdata = response.json()
    if jdata['total'] == 0:
        #print('no info')
        pass
    else:
        if val:
            return create_tmp_to_clipboard(
                response.json(),
                header_info,
                val,
                None)
        else:
            status, parsed_Data = json_parser.parse_urlscan(
                response.json(),
                query)
            if status == 'ok':
                return create_tmp_to_clipboard(
                    parsed_Data,
                    header_info,
                    val,
                    'print_row_table')
            elif status == 'KeyError':
                return create_tmp_to_clipboard(
                    parsed_Data,
                    header_info,
                    val,
                    None)


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
    header_spread = (
        'IP address/Domain was used to spread malware '
        + query)
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
    jdata = response.json()
    if jdata['query_status'] != 'ok':
        #print('no info')
        pass
    else:   
        if val:
            return create_tmp_to_clipboard(
                response.json(),
                header_spread,
                val,
                None)
        else:
            status, parsed_Data = json_parser.parse_urlhause(
                response.json(),
                query)
            if status == 'ok':
                return create_tmp_to_clipboard(
                    parsed_Data,
                    header_spread,
                    val,
                    'print_row_table')
            elif status == 'KeyError':
                return create_tmp_to_clipboard(
                    parsed_Data,
                    header_spread,
                    val,
                    None)


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
    header_compromised = (
        'Compromised Information '
        + query + '\n')
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
        return create_tmp_to_clipboard(
            response.json(),
            header_compromised,
            val,
            None)
    else:
        status, parsed_Data = json_parser.parse_shodan(
            response.json(),
            query)
        if status == 'ok':
            return create_tmp_to_clipboard(
                parsed_Data,
                header_compromised,
                val,
                'print_table')
        elif status == 'KeyError':
            return create_tmp_to_clipboard(
                parsed_Data,
                header_compromised,
                val,
                None)


def apility_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    # --- API info ---
    header_reputation = (
        'Reputation and activity through time '
        + query + '\n')
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
        #print(headers)
        url = get_url_ip+query
        #print(url)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            if val:
                return create_tmp_to_clipboard(
                    response.json(),
                    header_reputation,
                    val,
                    None)
            else:
                return create_tmp_to_clipboard(
                    json_parser.parse_apility(response.json(), query),
                    header_reputation,
                    val,
                    'print_row_table')
        elif response.status_code == 400:
            # print('maybe ip clean')
            """
            return create_tmp_to_clipboard(
                    'not sufficient data is availiable',
                    header_reputation,
                    val,
                    'n/a')"""
            pass

        else:
            pass


def hybrid_query(
        query: str,
        type: str,
        val: bool,
        sha_sum: list = None) -> dict:
    # --- API info ---
    header_association = (
        'Association with malware information '
        + query + '\n')
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
        url = data['API info']['hybrid']['query_ip']
        # The api url
        data = {'host': query}
        headers = {
            'accept': 'application/json',
            'user-agent': 'Falcon Sandbox',
            'Content-Type': 'application/x-www-form-urlencoded',
            'api-key': api_key}
        # The request headers
        response = requests.post(
            url,
            headers=headers,
            data=data)
        #print(response.status_code)
        #print(response.content)
    else:
        pass
    jdata = response.json()
    if jdata["count"] == 0:
        """
        return create_tmp_to_clipboard(
            'not sufficient data is availiable',
            'Association with malware information {}\n'.format(query),
            val,
            'n/a')"""
        pass
    else:
        if val:
            return create_tmp_to_clipboard(
                    response.json(),
                    header_association,
                    val,
                    None)
        else:
            return create_tmp_to_clipboard(
                    json_parser.parse_hybrid(response.json(), query),
                    header_association,
                    val,
                    'print_row_table')


def socket_connection_query(
        query: str,
        query_type: str,
        val: bool) -> dict:
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
    # --- Status ---
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Check connection')
    print(iconNone + ' ' + colorString, end='')
    print(' for ' + colorQuery)
    # --- Check query type ---
    if query_type == "domain":
        try:
            ipAddr = socket.gethostbyname(query)
            print(ipAddr)
            addrInfo = check_ip(socket.getaddrinfo(query, 80)[0][4][0])
            print(addrInfo)
            if ipAddr == addrInfo:
                url_http = 'http://www.' + query
                print(url_http)
                url_https = 'https://www.' + query
                print(url_https)
                wapperlazer_query(url_http, False)
                scan_ports(ipAddr, 10)             
            else:
                url_http = 'http://www.' + query
                print(url_http)
                url_https = 'https://www.' + query
                print(url_https)
                wapperlazer_query(url_http, False)
                scan_ports(ipAddr, 10)
        except socket.gaierror:
            print("Can't estabish connection to {}".format(query))
    elif query_type == "ip":
        try:
            hostName = socket.gethostbyaddr(query)[0]
            #print(hostName)
            hostName = '.'.join(hostName.split('.')[1:])
            print(hostName)
            input("[✔]")
            check = input("is this the correct domain for this ip ?")
            if check == 'yes':
                wapperlazer_query(hostName, False)
            elif check == 'no':
                url_http = input("insert the correct domain for this ip: ")
                wapperlazer_query(url_http, False)
            scan_ports(query, 10)
        except socket.herror:
            print("Can't estabish connection to {}".format(query))


def wapperlazer_query(
        query: str,
        val: bool) -> dict:
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
    header_wrapper = (
        '\nVarious technology scanned with wrapperlazer ' + query)    
    # --- API ---
    data = get_api()
    api = (data['API info']['wappalyzer']['api'])
    # --- Status ---
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Check Wrapperlazer')
    print(iconNone + ' ' + colorString, end='')
    print(' for ' + colorQuery)
    # --- query ---
    headers = {
        'X-Api-Key': api}
    url = "https://api.wappalyzer.com/lookup/v1/?url=" + query
    response = requests.get(url, headers=headers)

    parsed_Data = response.json()
    #print(parsed_Data)
    if val:
        return create_tmp_to_clipboard(
                parsed_Data,
                header_wrapper,
                val,
                None)
    else:
        status, parsed_Data = json_parser.parse_wrapperlazer(
                response.json(),
                query)
        return create_tmp_to_clipboard(
            parsed_Data,
            header_wrapper,
            val,
            'print_row_table')


threads = []
open_ports = {}

top_100_ports = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30,
    32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85,
    88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135,
    139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255,
    256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416,
    417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512,
    513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587,
    593, 616, 617]


def try_port(ip, port, delay, open_ports):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #socket.AF_INET, socket.SOCK_STREAM
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(delay)
    result = sock.connect_ex((ip, port))
    if result == 0:
        open_ports[port] = 'open'
        return True
    else:
        open_ports[port] = 'closed'
        return None


def scan_ports(ip, delay):
    # --- Status ---
    colorQuery = (Fore.RED + ip)
    colorString = (Fore.GREEN + 'Check Open Ports')
    print(iconNone + ' ' + colorString, end='')
    print(' for ' + colorQuery)
    for port in top_100_ports:
        thread = threading.Thread(
            target=try_port,
            args=(ip, port, delay, open_ports))
        threads.append(thread)

    for i in range(0, 100):
        threads[i].start()

    for i in range(0, 100):
        threads[i].join()

    for i in top_100_ports:
        if open_ports[i] == 'open':
            print('port number ' + str(i) + ' is open')
        if i == 617:
            print('\nscan complete!')
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
    test = '''### Attackers -> {}
### Victim   -> {}
### Context   -> {}'''.format(
                head.get("attackers", "Not found!"),
                head.get("victim", "Not found!"),
                head.get("context", "Not found!"))
    #print(test)
    return test


def text_body(body):
    try:
        for key, val in body.items():
            yield (('\n{} -> {}').format(key, val))
    except AttributeError:
        pass


def text_body_table(body: dict):
    try:
        for key, val in body.items():
            yield [str(key), str(val)]
    except AttributeError:
        print('attribute error')
        pass


def check_ip(ipv4_address):
    ipv4_pattern = (r"""^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$)$""")
    matches_public = re.search(ipv4_pattern, ipv4_address)
    if matches_public:
        return matches_public.group(0)


def manual_mode(attacker: list, victim: list, verbosity: bool, sha_sum: list = None):
    # check if argpase values are null
    if attacker is None:
        while True:
            attacker = input("attacker data (ip or domain): ").split(', ')
            if list(check_query_type(attacker)):
                print(attacker)
                victim = input("victim data (ip or domain): ").split(', ')
                if list(check_query_type(victim)):
                    print(victim)
                    break
                else:
                    continue
            else:
                continue
        attacker_list = [item.replace(' ', '') for item in attacker]
        simple_dict = {'attackers': attacker_list}
        victim_list = [item.replace(' ', '') for item in victim]
        simple_dict = {'attackers': victim_list}
        simple_dict.update({'victim': victim_list})
        main.collector(simple_dict, verbosity)
    else:
        # --- Complete manual mode ---
        attacker_list = [item.replace(' ', '') for item in attacker]
        simple_dict = {'attackers': attacker_list}
        victim_list = [item.replace(' ', '') for item in victim]
        simple_dict.update({'victim': victim_list})    
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


def printTable(tbl: Union[str, List[Union[str, List[str]]]], borderHorizontal='-', borderVertical='|', borderCross='+'):
    if isinstance(tbl, str):
        tbl = tbl.split('\n')
    string = ''
    try:
        # get the rows split by the values
        rows = []
        for row in tbl:
            if isinstance(row, str):
                row = row.split(', ')
            rows.append(row)

        # find the longests strings
        lenghts = [[] for _ in range(len(max(rows, key=len)))]
        for row in rows:
            for idx, value in enumerate(row):
                lenghts[idx].append(len(value))
        lengths = [max(lenght) for lenght in lenghts]

        # create formatting string with the length of the longest elements
        f = borderVertical + borderVertical.join(' {:>%d} ' % l for l in lengths) + borderVertical
        s = borderCross + borderCross.join(borderHorizontal * (l+2) for l in lengths) + borderCross
        string += s + '\n'
        print(s)
        for row in rows:
            string += f.format(*row) + '\n'
            print(f.format(*row))
            string += s + '\n'
            print(s)
        return string
    except ValueError:
        print('Value error')
        create_tmp_to_clipboard(tbl, 'test header', False, 'error')
        pass


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
        string += '\n' + s + '\n'
        if len(s) < 100:
            print(s)
        for row in tbl:
            string += f.format(*row) + '\n'
            if len(s) < 100:
                print(f.format(*row))
            string += s + '\n'
            if len(s) < 100:
                print(s)
        return string
    except TypeError:
        print('TypeError')
        #create_tmp_to_clipboard(tbl, 'test header', False, 'error1')
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


def check_query_type(data: list) -> str:
    result = []
    for string in data:
        ipv4_pattern = (r"""^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$)$""")
        matches_public = re.search(ipv4_pattern, string)
        if matches_public:
            result.append((matches_public.group(0), 'ip')) # or i instead of matches_public.group(0)
        else:
            pass

        domain_pattern = r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
        matches_domain = re.search(domain_pattern, string)
        if matches_domain:
            result.append((matches_domain.group(0), 'domain'))
        else:
            pass

        hash_pattern = (r"[a-f0-9]{32,128}")
        match_hash = re.search(hash_pattern, string, re.IGNORECASE)
        if match_hash:
            result.append((match_hash.group(0), 'hash'))
        else:
            pass
    return result


# ===================== ************* ===============================
# ----------Copy information to tmp file and then to clipboard-------
# ===================== ************* ===============================
def create_tmp_to_clipboard(
        data: dict,
        header_data: str,
        val: bool,
        print_type: str,
        path: str = path_default,
        fd: int = fd_default) -> None:
    try:
        with os.fdopen(fd, 'a+', encoding='utf-8', closefd=False) as tmp:
            if val:
                tmp.write('\n')
                tmp.write(header_data)
                tmp.write(json.dumps(data))
                tmp.write('\n')
                pass
            else:
                # print with tables and what i think is usefull
                if print_type == 'print_table':
                    #print('print_table')
                    #print(type(data))
                    tableContent = text_body_table(data)
                    #print(type(tableContent))
                    tmp.write('\n')
                    tmp.write(header_data)
                    tmp.write('{}'.format(printTable(tableContent)))
                elif print_type == 'print_row_table':
                    tmp.write('\n')
                    tmp.write(header_data)                          
                    tableContentRow = printTable_row(data)
                    tmp.write('{}'.format(tableContentRow))
                    pass
                elif print_type == 'error':
                    for i in data:
                        tmp.write(i)
                elif print_type == 'normal':
                    tmp.write('\n')
                    tmp.write(header_data)
                    for i in text_body(data):
                        tmp.write(i)
                    tmp.write('\n')
                elif print_type == 'ticket_header':
                    tmp.write('\n')
                    header = text_header(data)
                    #print(header)
                    for i in header:
                        tmp.write(i)
                    tmp.write('\n')
                elif print_type == 'n/a':
                    tmp.write('\n')
                    tmp.write(header_data)
                    tmp.write(data)
                    tmp.write('\n')
                else:
                    tmp.write('\n')
                    tmp.write(header_data)
                    tmp.write(json.dumps(data, indent=2, sort_keys=True))
                    tmp.write('\n')
                pass
            #  ===================== ************* ===========================
            # ------ IP addresses are getting worked here --------------------
            # ===================== ************* ============================
            # ip_addresses = info['attackers']
            # tmp.write(text_header(info))
            tmp.seek(0)
            content = tmp.read()
            pyperclip.copy(content)
            tmp.close()
            
    finally:
        # print(path)
        #time.sleep(20)
        """
        if content == '':
            print('\n' + iconError + ' No ticket was copied to clipboard')
            print("\n\nRemoving tmp files... Please wait")
        else:
            print('\n' + iconOK, end='')
            print(' Ticket was copied to clipboard successfully')
            print("\n\nRemoving tmp files... Please wait")
        os.remove(path)
        https://stackoverflow.com/questions/24984887/closing-a-file-descriptor-ive-used-with-fdopen
        """
        
        pass



"""
ip = 'cybaze.it'
socket_connection_query(ip, 'domain', False)


test_dic = {'ciao mondo': 25}
create_tmp_to_clipboard(test_dic, 'test header', False, 'error')


ip = '91.80.37.231'


domain = 'atracktr.info'
virustotal_query(ip, 'ip', False)
#progressbar_ip(ip)

iphub_query(ip, 'ip', False)
#progressbar_ip(ip)


getipintel_query(ip, 'ip', False)
#progressbar_ip(ip)

shodan_query(ip, 'ip', False)
#progressbar_ip(ip)


threatcrowd_query(ip, 'ip', False)
#progressbar_ip(ip)


hybrid_query(ip, 'ip', False)
#progressbar_ip(ip)


apility_query(ip, 'ip', False)
#progressbar_ip(ip)

abuseipdb_query(ip, 'ip', False)
#progressbar_ip(ip)

urlscan_query(ip, 'ip', False)
#progressbar_ip(ip)

urlhause_query(ip, 'ip', False)
#progressbar_ip(ip)


threatminer_query(ip, 'ip', False)
#progressbar_ip(ip)"""