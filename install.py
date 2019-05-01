import os
import json
from pathlib import Path
from argparse import ArgumentParser

NAME = "soc-analyst-arsenal"
api_info = """
{"API info": {
    "urlscan.io": {
        "api": "Your API key here",
        "comment": "login to website to create your API",
        "query_domain": "https://urlscan.io/api/v1/search/?q=domain:",
        "query_ip": "https://urlscan.io/api/v1/search/?q=ip:"
    },
    "abuseipdb": { 
        "api": "Your API key here",
        "comment": "login to website to create your API",
        "url": "https://www.abuseipdb.com/check/IP/json?key=API&days=120"
    },
    "urlhaus": {
        "api": "Your API key here",
        "comment": "login using twitter account on this site https://urlhaus.abuse.ch/api/#account",
        "url": "https://urlhaus-api.abuse.ch/v1/url/",
        "querry_host_url": "https://urlhaus-api.abuse.ch/v1/host/"
    },
    "virustotal": {
        "api" : "Your API key here",
        "comment" : "sign up to virustotal",
        "file_url": "https://www.virustotal.com/vtapi/v2/file/report",
        "query_ip" : "https://www.virustotal.com/vtapi/v2/ip-address/report",
        "query_domain": "https://www.virustotal.com/vtapi/v2/domain/report",
        "scan_url": "https://www.virustotal.com/vtapi/v2/url/scan",
        "comments_url": "https://www.virustotal.com/vtapi/v2/comments/get"
    },
    "shodan":{
        "api":"Your API key here",
        "query_ip": "https://api.shodan.io/shodan/host/{}?key={}"
    },
    "apility":{
        "url_ip_request": "https://api.apility.net/v2.0/ip/",
        "url_domain_request" : "https://api.apility.net/baddomain/",
        "api": "Your API key here"
    },
    "hybrid":{
        "api":"Your API key here",
        "query_ip":"https://www.hybrid-analysis.com/api/v2/search/terms"
    },
    "iphub":{
        "api": "Your API key here",
        "query_ip": "http://v2.api.iphub.info/ip/"
    },
    "fofa":{
        "api": "Your API key here",
        "query_all": "https://fofa.so/api/v1/search/all",
        "email": "Your Email Here"
    },
    "getipintel":{
        "query_ip": "http://check.getipintel.net/check.php?ip={}&contact={}&format=json",
        "email":"Your Email Here"
    },
    "threatminer":{
        "query_domain": "https://api.threatminer.org/v2/domain.php?q={}&rt=1",
        "query_ip": "https://api.threatminer.org/v2/host.php?q={}&rt=6"
    },
    "threatcrowd":{
        "query_ip": "https://www.threatcrowd.org/searchApi/v2/ip/report/",
        "query_domain": "https://www.threatcrowd.org/searchApi/v2/domain/report/"
    }
}}
"""

program_data = Path('c:/') / 'ProgramData' / 'api.json'


def install():
    data = json.loads(api_info)
    api_urlscan = input("please insert api key for urlscan.io: ")
    data['API info']['urlscan.io']['api'] = api_urlscan
    api_abuseipdb = input("please insert api key for abuseipdb: ")
    data['API info']['abuseipdb']['api'] = api_abuseipdb
    api_urlhaus = input("please insert api key for urlhaus: ")
    data['API info']['urlhaus']['api'] = api_urlhaus
    api_virustotal = input("please insert api key for virustotal: ")
    data['API info']['virustotal']['api'] = api_virustotal
    api_threatminer = input("please insert api key for threatminer: ")
    data['API info']['threatminer']['api'] = api_threatminer
    api_apility = input("please insert api key for apility: ")
    data['API info']['apility']['api'] = api_apility
    api_hybrid = input("please insert api key for hybrid: ")
    data['API info']['hybrid']['api'] = api_hybrid
    api_getipintel = input("please insert api key for getipintel: ")
    data['API info']['getipintel']['email'] = api_getipintel

    with open(str(program_data), 'w') as api_file:
        json.dump(data, api_file)


def uninstall():
    print("Uninstalling...")
    os.remove(str(program_data))


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '--uninstall', '-u',
        action='store_true',
        help=f"Remove {NAME} from your system."
    )
    args = parser.parse_args()
    if args.uninstall:
        uninstall()
    else:
        install()


#uninstall()
#install()
#print(os.environ['PATH'])