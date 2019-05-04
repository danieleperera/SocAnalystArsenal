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
    colorString = (Fore.GREEN + 'VirusTotal')
    print(iconNone + ' ' + colorString, end='')
    print(' checking WhoIs Information for ' + colorQuery)
    # --- Check query type ---
    if query_type == "domain":
        try:
            ipAddr = socket.gethostbyname(query)
            print(ipAddr)
        except socket.gaierror:
            print("Can't estabish connection to {}".format(query))
    elif query_type == "ip":
        try:
            hostName = socket.gethostbyaddr(query)
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
### Victims   -> {}
### Context   -> {}'''.format(
                head.get("attackers", "Not found!"),
                head.get("victims", "Not found!"),
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
    for string in data:
        ipv4_pattern = (r"""^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$)$""")
        matches_public = re.search(ipv4_pattern, string)
        if matches_public:
            yield matches_public.group(0), 'ip' # or i instead of matches_public.group(0)

        domain_pattern = r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
        matches_domain = re.search(domain_pattern, string)
        if matches_domain:
            yield matches_domain.group(0), 'domain'

        hash_pattern = (r"[a-f0-9]{32,128}")
        match_hash = re.search(hash_pattern, string, re.IGNORECASE)
        if match_hash:
            yield match_hash.group(0), 'hash'


# ===================== ************* ===============================
# ----------Copy information to tmp file and then to clipboard--------------------
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


ip = '91.80.37.231'
socket_connection_query(ip, 'ip', False)
"""
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