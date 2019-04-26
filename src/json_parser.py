# -*- coding: utf-8 -*-
# -*- style: PEP8 -*-
# ===================== ************* ===============================
# ------------------- parse JSON INFOMATION -----------------------
# ===================== ************* ===============================
import time
from colorama import Fore
#import api_query
iconNone = (Fore.YELLOW + '[!]')


def parse_virustotal(jdata: dict, query: str) -> dict:
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
    try:
        whois_dict = {}
        if jdata['response_code'] == -1:
            pass
            return
        else:

            whois_dict['Country'] = jdata.get('country', 'not found')
            whois_dict['Continent'] = jdata.get('continent', 'not found')
            whois_dict['Organization'] = jdata.get('as_owner', 'not found')
            whois_dict['Autonomous System Number'] = jdata.get('asn', 'not found')
            # --- only sample detected for certain ip or domain
            # whois_dict = {k: str.encode(v, 'ascii', 'replace')
            # for k,v in whois_dict.items()}
            
            for index, item in enumerate(
                    jdata['detected_downloaded_samples']):
                whois_dict["Detected samples "] = (
                    'that communicate this ip address -> {}'.format(query))
                whois_dict[f"detected samples_{index}"] = item['sha256']
                # simple_dict[f"file_score_{index}"] =
                # str(item['positives'])+'/'+str(item['total'])
            for index, item in enumerate(jdata['detected_urls']):
                whois_dict[f"detected_urls_{index}"] = item['url']
                # simple_dict[f"urls_score_{index}"] =
                # str(item['positives'])+'/'+str(item['total'])
            # print(whois_dict)
            # detected_dict = {k: str.encode(v, 'ascii', 'replace')
            # for k,v in detected_dict.items()}
        status = 'ok'
        return status, whois_dict
    except KeyError:
        #print('\nkey error occurred\n')
        status = 'KeyError'
        return status, jdata
        pass


def parse_iphub(jdata: dict, query: str) -> dict:
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


def parse_getipintel(jdata: dict, query: str) -> dict:
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
        simple_dict['Proxy/VPN/Tor'] = "{} %".format(float(score) * int(100))
        return simple_dict


def parse_shodan(jdata: dict, query: str) -> dict:
    simple_dic = {}
    try:
        for index, item in enumerate(jdata['data']):
            hd = (item['data'])
            simple_dic[f'Detected_{index+1}_open_port: '] = item['port']
            simple_dic[f'Detected_info_{index+1}'] = "{} {}".format(
                hd.splitlines()[0],
                hd.splitlines()[1])
        # simple_dic = {k: str.encode(v, 'utf-8', 'replace')
        # for k,v in simple_dic.items()}
        status = 'ok'
        return status, simple_dic
    except IndexError:
        print("Index Error")
        status = 'IndexError'
        return status, jdata
    except KeyError:
        status = 'KeyError'
        #print('\nkey error occurred\n')
        return status, jdata


def parse_threatcrowd(jdata: dict, query: str) -> dict:
    '''
    ```
    jdata = {
  "response_code": 1,
  "resolutions": [
    {
      "last_resolved": "2015-02-17",
      "domain": "tvgate.rocks"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "nice-mobiles.com"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "nauss-lab.com"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "iwork-sys.com"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "linkedim.in"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "fpupdate.info"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "ineltdriver.com"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "flushupdate.com"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "flushupate.com"
    },
    {
      "last_resolved": "2015-02-17",
      "domain": "ahmedfaiez.info"
    },
    {
      "last_resolved": "2014-02-14",
      "domain": "advtravel.info"
    },
    {
      "last_resolved": "2014-05-27",
      "domain": "nartu.de"
    },
    {
      "last_resolved": "2015-02-19",
      "domain": "www.fpupdate.info"
    },
    {
      "last_resolved": "2014-03-22",
      "domain": "advtravel.info\r"
    },
    {
      "last_resolved": "2014-06-08",
      "domain": "ahmedfaiez.info\r"
    },
    {
      "last_resolved": "2014-08-22",
      "domain": "flushupate.com\r"
    },
    {
      "last_resolved": "2014-11-07",
      "domain": "ineltdriver.com\r"
    },
    {
      "last_resolved": "2015-09-21",
      "domain": "gbartu.de"
    },
    {
      "last_resolved": "2015-09-28",
      "domain": "vartu.de"
    },
    {
      "last_resolved": "2019-04-10",
      "domain": "NS2.ATYAFHOSTING.INFO"
    },
    {
      "last_resolved": "2019-04-11",
      "domain": "ns1.atyafhosting.info"
    },
    {
      "last_resolved": "2019-04-15",
      "domain": "188.40.75.132"
    }
  ],
  "hashes": [
    "003f0ed24b5f70ddc7c6e80f9c4dac73",
    "027fc90c13f6d87e1f68d25b0d0ec4a7",
    "088420b7e56c73d3d495230d42e0cb95",
    "1e52a293838464e4cd6c1c6d94a55793",
    "2219f3941603262dc3478c60df3b02f6",
    "238b48338c14c8ea87ff7ccab4544252",
    "2607abe604832363514eb58c33a682fc",
    "2986d9af413cd09d9ffdb40040e5c180",
    "2b3baed817a79109824d3a8a94f6c317",
    "2bce2ccd484a063e5e432a6f651782d9",
    "4377b17d7984838993b998c4bab97925",
    "4907a68a3ff0f010ed74214f957746c0",
    "63c480b1cc601b02b4acb30309b007e6",
    "686779709226c6727bd9ebc4b1ff21b1",
    "6b4248a01a26ff07a85b5316702a2f5f",
    "7075c9a874ab5b0c27942714394f3885",
    "73c46bacc471db08a6c0e31caef3f9e8",
    "74d8b882efae9fea1787f1558589fecb",
    "76f74b24480bc1a42998c9440ddc2fad",
    "7ac102b740b299824e34394f334b5508",
    "7ed79032a1ad8535242428e69507ca0a",
    "8a9b52ff90bbd585907694e68551b991",
    "8bbad466f2257e05f66ece621ccf2056",
    "9469ff12c582cf7943582dd28a1920cc",
    "a0b76ea08917a9dd785a0a1a6ae6eebe",
    "a4a390f90be49b2bb51194d0844fed7f",
    "a59399c7608d140dc9cb5dffcb46f1d9",
    "aefea9d795624da16d878dc9bb81bf87",
    "b08a67892d2198aeb2826b398f8c6c74",
    "bd54d70d473d45b75cc8bf1fbe6fa022",
    "d048a6a8377a865f07cbc2429ffaa3e7",
    "dff746868a1559de9d25037e73c06c52",
    "e1d2543aba350a83c968872fbe957d85",
    "f3d6bb7addc88ad45f79c5199f8db2e0",
    "f78fcd4eaf3d9cd95116b6e6212ad327",
    "fa6fbd1dd2d58885772bd0b37633d5d7"
  ],
  "references": [],
  "votes": -1,
  "permalink": "https://www.threatcrowd.org/ip.php?ip=188.40.75.132"
}
```
    '''
    simple_dic = {}
    try:
        simple_dic['link'] = jdata.get('permalink', 'n/a')
    except IndexError:
        # print("Index Error")
        pass
    finally:
        return simple_dic


def parse_hybrid(jdata: dict, query: str) -> list:
    """
    ```
    jdata = {
                "search_terms": [
                    {
                    "id": "host",
                    "value": "188.40.75.132"
                    }
                ],
                "count": 2,
                "result": [
                    {
                    "verdict": "malicious",
                    "av_detect": 1,
                    "threat_score": 43,
                    "vx_family": "Unrated site",
                    "job_id": "5b5195967ca3e125e26f0645",
                    "sha256": "
                        502b6d5e3199250fa210ee04fda0bff7e32020889869cdbd8cb871774baae996",
                    "environment_id": 120,
                    "analysis_start_time": "2018-07-20 08:54:48",
                    "submit_name": "http188.40.75.132.url",
                    "environment_description": "Windows 7 64 bit",
                    "size": 45,
                    "type": "Null",
                    "type_short": "url"
                    },
                    {
                    "verdict": "malicious",
                    "av_detect": 1,
                    "threat_score": 20,
                    "vx_family": "Unrated site",
                    "job_id": "5b2ba9b87ca3e162a95979d9",
                    "sha256": "
                        502b6d5e3199250fa210ee04fda0bff7e32020889869cdbd8cb871774baae996",
                    "environment_id": 100,
                    "analysis_start_time": "2018-06-21 15:36:36",
                    "submit_name": "http188.40.75.132.url",
                    "environment_description": "Windows 7 32 bit",
                    "size": 45,
                    "type": "Null",
                    "type_short": "url"
                    }
                ]
                }
    ```
    """
    content_list = []
    try:
        c = jdata["count"]
        header_list = [
            'verdict',
            'av_detect',
            'threat_score',
            'sha256',
            'submit_name',
            'analysis_start_time']
        body_list = []
        content_list.append(header_list)
        for i in range(0, c):
            body_list.extend([
                jdata["result"][i]['verdict'],
                jdata["result"][i]['av_detect'],
                jdata["result"][i]['threat_score'],
                jdata["result"][i]['sha256'],
                jdata["result"][i]['submit_name'],
                jdata["result"][i]['analysis_start_time']])
            content_list.append(body_list)
        return content_list
    except IndexError:
        print("index Error")


def parse_apility(jdata: dict, query: str) -> list:
    try:
        reputation = jdata['fullip']['history']['activity']
        if reputation is None:
            string = '\nThis IP has not been blacklisted since 1 year'
            return string
        else:
            content_list = []
            content_list.append(list(reputation[0].keys()))
            for i in range(len(reputation)):
                tp = reputation[i]['timestamp']
                date = time.strftime('%Y-%m-%d', time.localtime(tp/1000))
                reputation[i].update(timestamp=date)
                content_list.append(list(reputation[i].values()))
    except IndexError:
        pass
    finally:
        return content_list
    pass


def parse_urlhause(jdata: dict, query: str) -> list:
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
                    "urlhaus_reference": "
                        https://urlhaus.abuse.ch/host/187.107.132.33/",
                    "host": "187.107.132.33",
                    "firstseen": "2019-04-11 10:06:01 UTC",
                    "url_count": "1",
                    "blacklists": {
                        "spamhaus_dbl": "unknown_return_code",
                        "surbl": "not listed"},
                    "urls": [{
                        "id": "175438",
                        "urlhaus_reference": "
                            https://urlhaus.abuse.ch/url/175438/",
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
    content_list = []
    try:
        c = int(jdata["url_count"])
        #print(c)
        header_list = [
            'status',
            'date',
            'threat',
            'category',
            'reporter',
            'url']
        body_list = []
        content_list.append(header_list)
        for i in range(0, c):
            body_list.extend([
                jdata["urls"][i]['url_status'],
                jdata["urls"][i]['date_added'][0:10],
                jdata["urls"][i]['threat'],
                ",".join(str(x) for x in jdata["urls"][i]['tags']),
                jdata["urls"][i]['reporter'],
                jdata["urls"][i]['url']])
            content_list.append(body_list)
        status = 'ok'
        return status, content_list
    except KeyError:
        #print('\nkey error occurred\n')
        status = 'KeyError'
        return status, jdata


def parse_urlscan(jdata: dict, query: str) -> list:
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
      "result": "
        https://urlscan.io/api/v1/result/336d51e3-e11c-4ed9-a687-dc4f3114f154"
    }
    ```

    return
    dict -- Returns dict of values that i chose.

    """
    content_list = []
    try:
        c = jdata["total"]
        header_list = [
            'visibility',
            'time',
            'source',
            'url',
            'server',
            'domain']
        #print(header_list)
        body_list = []
        content_list.append(header_list)
        for i in range(0, c):
            #print(i)
            body_list.extend([
                jdata["results"][i]['task']['visibility'],
                jdata["results"][i]['task']['time'][0:10],
                jdata["results"][i]['task']['source'],
                jdata["results"][i]['task']['url'],
                jdata["results"][i]['page']['server'],
                jdata["results"][i]['page']['domain']])
            content_list.append(body_list)
            pass
        #results = {"urlscan": jdata['results'][0]['task']['url']}
        status = 'ok'
        return status, content_list
    except KeyError:
        #print('\nkey error occurred\n')
        status = 'KeyError'
        return status, jdata


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


def parse_abuseipdb(jdata: dict, query: str) -> dict:
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
    data_from_abuseipdb = {}
    try:
        result_with_correct_category = (
            max(
                jdata,
                key=lambda x:
                (len(x['ip']), len(x['category']))))
        data_from_abuseipdb = {
            "attacker": result_with_correct_category['ip'],
            "category":
            retruncategory(result_with_correct_category['category']),
            "country": result_with_correct_category['country'],
            "abuseConfidenceScore":
            result_with_correct_category['abuseConfidenceScore']}
        status = 'ok'
        return status, data_from_abuseipdb
    except KeyError:
        #print('\nkey error occurred\n')
        status = 'KeyError'
        return status, jdata
    except TypeError:
        print('type error')
        pass


def parse_threatminer(jdata: dict, query: str) -> dict:
    try:
        return jdata
    except TypeError:
        print('type error')


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
            detected_dict["found_positives"] = ("{} / {}".format(
                resp_json['positives'],
                resp_json['total']))
            # detected_dict["permalink"] = resp_json["permalink"]
            if detected is True:
                # Print Engines which detect malware.
                # print(f'{av_name} detected Malware!')
                # Add detected engine name and it's result to the
                # detected_dict.
                detected_dict[av_name] = resp_json['scans'][av_name]['result']
    return detected_dict


def querry_status_virustotal_domain(
        positions: dict,
        domain_to_view: str) -> dict:
    if positions['response_code'] == -1:
        print('[!] No result on virustotal')
        return False, False
    else:
        try:
            whois_dict = {}
            whois_dict = dict(
                pair.split(": ") for pair in positions["whois"].split("\n"))
            # whois_dict = {k: str.encode(v, 'ascii', 'replace')
            # for k,v in whois_dict.items()}
            # --- only sample detected for certain ip or domain

        except AttributeError:
            print('No whois data found')
        category_from_virustotal = {}
        category_from_virustotal['Opera domain info'] = positions.get(
            'Opera domain info',
            'Not found')
        category_from_virustotal['BitDefender domain info'] = positions.get(
            'BitDefender domain info',
            'Not found')
        category_from_virustotal['Dr.Web category'] = positions.get(
            'Dr.Web category',
            'Not found')
        category_from_virustotal['Malwarebytes Hosts info'] = positions.get(
            'Malwarebytes hpHosts info',
            'Not found')
        # category_from_virustotal = {k: str.encode(v, 'ascii', 'replace')
        # for k,v in category_from_virustotal.items()}
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
print(urlhause_query(ip, 'domain', True))
"""
