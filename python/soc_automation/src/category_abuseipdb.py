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