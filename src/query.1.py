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
import tempfile
import pyperclip
from typing import List, Union
# victim imports
import socket
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
            else:
                pass
        except socket.gaierror:
            print("Can't estabish connection to {}".format(query))
    elif query_type == "ip":
        try:
            hostName = socket.gethostbyaddr(query)
            print(hostName)
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

    params = {
        'url', query}

    response = requests.get(
        'https://api.wappalyzer.com/lookup/v1/',
        headers=headers,
        params=params)

    print(response.json())

# ===================== ************* ===============================
# ---------- Various Checks and printing ticket --------------------
# ===================== ************* ===============================


def check_ip(ipv4_address):
    ipv4_pattern = (r"""^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$)$""")
    matches_public = re.search(ipv4_pattern, ipv4_address)
    if matches_public:
        return matches_public.group(0)


domain = 'gov.lk'
socket_connection_query(domain, 'domain', False)

"""
test = requests.get("http://api.hackertarget.com/nmap/?q=43.224.127.40")
print(test.text)"""
