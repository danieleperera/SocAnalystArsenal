# ===================== ************* ===============================
# ------------------- parse JSON INFOMATION -----------------------
# ===================== ************* ===============================


def parse_virustotal(jdata: dict, query: str, sha_sum: list = None) -> dict:
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
    if jdata['response_code'] == -1:
        print('[!] No result on virustotal')
        return False, False
    else:
        whois_dict = {}
        whois_dict['Country'] = jdata.get('country', 'not found')
        whois_dict['Continent'] = jdata.get('continent', 'not found')
        whois_dict['Organization'] = jdata.get('as_owner', 'not found')
        whois_dict['Autonomous System Number'] = jdata.get('asn', 'not found')
        # --- only sample detected for certain ip or domain
        #whois_dict = {k: str.encode(v, 'ascii', 'replace') for k,v in whois_dict.items()}
        try:
            for index, item in enumerate(
                    jdata['detected_downloaded_samples']):
                whois_dict["Detected samples "] = ('that communicate this ip address -> {}'.format(query))
                whois_dict[f"detected samples_{index}"] = item['sha256']
                #simple_dict[f"file_score_{index}"] = str(item['positives'])+'/'+str(item['total'])
            for index, item in enumerate(jdata['detected_urls']):
                whois_dict[f"detected_urls_{index}"] = item['url']
                #simple_dict[f"urls_score_{index}"] = str(item['positives'])+'/'+str(item['total'])
            # print(simple_dict)
            #detected_dict = {k: str.encode(v, 'ascii', 'replace') for k,v in detected_dict.items()}
        except KeyError:
            print('key error')
        finally:
            return whois_dict


def parse_iphub(jdata: dict, query: str, sha_sum: list = None) -> dict:
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
    jdata = {
        'ip': '188.40.75.132',
        'countryCode': 'DE',
        'countryName': 'Germany',
        'asn': 24940,
        'isp': 'HETZNER-AS',
        'block': 1,
        'hostname': '188.40.75.132'}
    ```

    return
    dict -- Returns dict of values that i chose.

    """
    try:
        errore = jdata['error']
        if errore == 'Invalid IP address or domain name':
            print('[!] No result on iphub')
    except KeyError:
        simple_dict = {}
        simple_dict['ip'] = jdata.get('ip', 'n/a')
        simple_dict['isp'] = jdata.get('isp', 'n/a')
        if jdata['block'] == 1:
            simple_dict['Proxy/VPN/Tor'] = 'yes'
        else:
            simple_dict['Proxy/VPN/Tor'] = 'not sufficient data'
        return simple_dict


def parse_getipintel(jdata: dict, query: str, sha_sum: list = None) -> dict:
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
    jdata = {
        'ip': '188.40.75.132',
        'countryCode': 'DE',
        'countryName': 'Germany',
        'asn': 24940,
        'isp': 'HETZNER-AS',
        'block': 1,
        'hostname': '188.40.75.132'}
    ```

    return
    dict -- Returns dict of values that i chose.

    """
    
    errore = jdata.get('status')
    if errore == 'error':
        print('[!] No result on iphub')
    else:
        simple_dict = {}
        simple_dict['ip'] = jdata.get('queryIP', 'n/a')
        simple_dict['isp'] = jdata.get('queryFlags', 'n/a')
        score = jdata.get('result', 'n/a')
        simple_dict['Proxy/VPN/Tor'] = "{} %".format(int(score) * int(100))
        return simple_dict


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


def querry_status_virustotal_domain(positions: dict, domain_to_view: str) -> dict:
    if positions['response_code'] == -1:
        print('[!] No result on virustotal')
        return False, False
    else:
        try:
            whois_dict = {}
            whois_dict = dict(pair.split(": ") for pair in positions["whois"].split("\n"))
            #whois_dict = {k: str.encode(v, 'ascii', 'replace') for k,v in whois_dict.items()}
            # --- only sample detected for certain ip or domain
            
        except AttributeError:
            print('No whois data found')
        category_from_virustotal = {}
        category_from_virustotal['Opera domain info'] = positions.get('Opera domain info', 'Not found')
        category_from_virustotal['BitDefender domain info'] = positions.get('BitDefender domain info', 'Not found')
        category_from_virustotal['Dr.Web category'] = positions.get('Dr.Web category', 'Not found')
        category_from_virustotal['Malwarebytes Hosts info'] = positions.get('Malwarebytes hpHosts info', 'Not found')
        #print(category_from_virustotal)
        #category_from_virustotal = {k: str.encode(v, 'ascii', 'replace') for k,v in category_from_virustotal.items()}
        return whois_dict, category_from_virustotal

"""
#hybrid_query('checkip.dyndns.org')
ip = '91.80.37.231'

print(virustotal_query(ip, 'ip', True))
print(shodan_query(ip, 'ip', True))
print(hybrid_query(ip, 'ip', True))
print(apility_query(ip, 'ip', True))
print(abuseipdb_query(ip, 'ip', True))
print(urlscan_query(ip, 'ip', True))
print(urlhause_query(ip, 'domain', True))"""

