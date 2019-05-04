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
        except socket.gaierror:
            print("Can't estabish connection to {}".format(query))
    elif query_type == "ip":
        try:
            hostName = socket.gethostbyaddr(query)[0]
            print(hostName)
        except socket.herror:
            print("Can't estabish connection to {}".format(query))
"""
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
                        'print_row_table')"""


def wapperlazer_query(
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
    # --- API ---
    data = get_api()
    api = (data['API info']['wappalyzer']['api'])
    # --- Status ---
    colorQuery = (Fore.RED + query)
    colorString = (Fore.GREEN + 'Check connection')
    print(iconNone + ' ' + colorString, end='')
    print(' for ' + colorQuery)

# ===================== ************* ===============================
# ---------- Various Checks and printing ticket --------------------
# ===================== ************* ===============================

ip = '43.224.127.40'
socket_connection_query(ip, 'ip', False)
"""
test_dic = {'ciao mondo': 25}
create_tmp_to_clipboard(test_dic, 'test header', False, 'error')

domain = 'gov.lk'
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