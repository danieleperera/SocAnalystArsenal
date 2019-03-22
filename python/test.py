import json
import requests
#y353THdFZsWpYMMA6vaarxv3nxJDVERiXQD9SCiL abuseipdb
#info_json = requests.get("https://www.abuseipdb.com/check/60.165.248.102/json?key=y353THdFZsWpYMMA6vaarxv3nxJDVERiXQD9SCiL&days=120")

with open("test.json","r") as f:
    contents = f.read()
    data = json.loads(contents)
    #print(type(data))

    bestresult = (max(data, key=lambda x: (len(x['ip']), len(x['category']))))
    #print(bestresult['ip'],bestresult['category'],bestresult['country'],bestresult['abuseConfidenceScore'])


    category_abuseipdb = {
        "3":"Fraud Orders",
        "4":"DDoS Attack",
        "5":"FTP Brute-Force",
        "6":"Ping of Death",
        "7":"Phishing",
        "8":"Fraud VoIP",
        "9":"Open Proxy",
        "10":"Web Spam",
        "11":"Email Spam",
        "12":"Blog Spam",
        "13":"VPN IP",
        "14":"Port Scan",
        "15":"Hacking Generic",
        "16":"SQL Injection",
        "17":"Spoofing",
        "18":"Brute-Force",
        "19":"Bad Web Bot",
        "20":"Exploited Host",
        "21":"Web App Attack",
        "22":"SSH",
        "23":"IoT Targeted",

    }

    def retruncategory():
        list=[]
        for category in bestresult['category']:
            nice = (category_abuseipdb[str(category)])
            list.append(nice)
        return list
    output_list = retruncategory()


    print("""\t\tIP attacker: {}
            \tCategory: {}
            \tCountry: {}
            \tAbuseConfidenceScore: {}%""".format(bestresult['ip'],", ".join(output_list),bestresult['country'],bestresult['abuseConfidenceScore']))
    
