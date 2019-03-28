import json

querry_ok = '''[{"ip":"167.99.81.228","category":[5,15],"created":"Thu, 10 Jan 2019 19:45:44 +0000","country":"United Kingdom","isoCode":"GB","isWhitelisted":false,"abuseConfidenceScore":0},{"ip":"167.99.81.228","category":[5,15],"created":"Thu, 10 Jan 2019 19:22:35 +0000","country":"United Kingdom","isoCode":"GB","isWhitelisted":false,"abuseConfidenceScore":0}]'''

querry_bad = '''[]'''


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
    list=[]
    for category in test_json:
        nice = (category_abuseipdb[str(category)])
        list.append(nice)
    return list





def querry_status_abuseipdb(positions):
    if positions == []:
        print('[!] No result on urlhause')
        return False
    else:
        result_with_correct_category = (max(positions, key=lambda x: (len(x['ip']), len(x['category']))))
        data_from_abuseipdb = {
        "attacker" : result_with_correct_category['ip'],
        "category" : retruncategory(result_with_correct_category['category']),
        "country" : result_with_correct_category['country'],
        "abuseConfidenceScore" : result_with_correct_category['abuseConfidenceScore']
        }
        print(data_from_abuseipdb)
        return data_from_abuseipdb
    

#print(querry_ip_response['total'])
querry_ip_response = json.loads(querry_bad)
querry_status_abuseipdb(querry_ip_response)
    