import json

querry_ok = '''{
   "scans": {
     "Bkav": {
       "detected": "False",
       "version": "1.3.0.9899",
       "result": "NULL",
       "update": "20190412"
     },
     "TotalDefense": {
       "detected": "False",
       "version": "37.1.62.1",
       "result": "NULL",
       "update": "20190412"
     },
     "MicroWorld-eScan": {
       "detected": "False",
       "version": "14.0.297.0",
       "result": "NULL",
       "update": "20190412"
     },
     "FireEye": {
       "detected": "False",
       "version": "29.7.0.0",
       "result": "NULL",
       "update": "20190412"
     },
     "CAT-QuickHeal": {
       "detected": "True",
       "version": "14.00",
       "result": "W97M.Emotet.Heur",
       "update": "20190411"
     },
     "ALYac": {
       "detected": "False",
       "version": "1.1.1.5",
       "result": "NULL",
       "update": "20190412"
     },
     "Malwarebytes": {
       "detected": "False",
       "version": "2.1.1.1115",
       "result": "NULL",
       "update": "20190412"
     },
     "Zillya": {
       "detected": "False",
       "version": "2.0.0.3794",
       "result": "NULL",
       "update": "20190410"
     },
     "SUPERAntiSpyware": {
       "detected": "False",
       "version": "5.6.0.1032",
       "result": "NULL",
       "update": "20190410"
     },
     "K7AntiVirus": {
       "detected": "True",
       "version": "11.38.30582",
       "result": "Trojan ( 00536d111 )",
       "update": "20190412"
     },
     "K7GW": {
       "detected": "True",
       "version": "11.38.30581",
       "result": "Trojan ( 00536d111 )",
       "update": "20190412"
     },
     "TheHacker": {
       "detected": "False",
       "version": "6.8.0.5.4154",
       "result": "NULL",
       "update": "20190411"
     },
     "Arcabit": {
       "detected": "False",
       "version": "1.0.0.845",
       "result": "NULL",
       "update": "20190412"
     },
     "Baidu": {
       "detected": "False",
       "version": "1.0.0.2",
       "result": "NULL",
       "update": "20190318"
     },
     "NANO-Antivirus": {
       "detected": "False",
       "version": "1.0.134.24576",
       "result": "NULL",
       "update": "20190412"
     },
     "Cyren": {
       "detected": "True",
       "version": "6.2.0.1",
       "result": "W97M/Downldr.CE.gen!Eldorado",
       "update": "20190412"
     },
     "Symantec": {
       "detected": "True",
       "version": "1.8.0.0",
       "result": "ISB.Downloader!gen76",
       "update": "20190412"
     },
     "ESET-NOD32": {
       "detected": "False",
       "version": "19183",
       "result": "NULL",
       "update": "20190412"
     },
     "TrendMicro-HouseCall": {
       "detected": "True",
       "version": "10.0.0.1040",
       "result": "Trojan.W97M.POWLOAD.SMRV07",
       "update": "20190412"
     },
     "Avast": {
       "detected": "False",
       "version": "18.4.3895.0",
       "result": "NULL",
       "update": "20190412"
     },
     "ClamAV": {
       "detected": "False",
       "version": "0.101.2.0",
       "result": "NULL",
       "update": "20190412"
     },
     "GData": {
       "detected": "False",
       "version": "A:25.21523B:25.14830",
       "result": "NULL",
       "update": "20190412"
     },
     "Kaspersky": {
       "detected": "False",
       "version": "15.0.1.13",
       "result": "NULL",
       "update": "20190412"
     },
     "BitDefender": {
       "detected": "False",
       "version": "7.2",
       "result": "NULL",
       "update": "20190412"
     },
     "Babable": {
       "detected": "False",
       "version": "9107201",
       "result": "NULL",
       "update": "20180918"
     },
     "AegisLab": {
       "detected": "False",
       "version": "4.2",
       "result": "NULL",
       "update": "20190412"
     },
     "Rising": {
       "detected": "False",
       "version": "25.0.0.24",
       "result": "NULL",
       "update": "20190412"
     },
     "Ad-Aware": {
       "detected": "False",
       "version": "3.0.5.370",
       "result": "NULL",
       "update": "20190412"
     },
     "Sophos": {
       "detected": "False",
       "version": "4.98.0",
       "result": "NULL",
       "update": "20190412"
     },
     "Comodo": {
       "detected": "False",
       "version": "30711",
       "result": "NULL",
       "update": "20190412"
     },
     "F-Secure": {
       "detected": "False",
       "version": "12.0.86.52",
       "result": "NULL",
       "update": "20190412"
     },
     "DrWeb": {
       "detected": "False",
       "version": "7.0.34.11020",
       "result": "NULL",
       "update": "20190412"
     },
     "VIPRE": {
       "detected": "False",
       "version": "74338",
       "result": "NULL",
       "update": "20190412"
     },
     "McAfee-GW-Edition": {
       "detected": "False",
       "version": "v2017.3010",
       "result": "NULL",
       "update": "20190412"
     },
     "CMC": {
       "detected": "False",
       "version": "1.1.0.977",
       "result": "NULL",
       "update": "20190321"
     },
     "Emsisoft": {
       "detected": "True",
       "version": "2018.4.0.1029",
       "result": "Trojan-Downloader.Macro.Generic.O (A)",
       "update": "20190412"
     },
     "SentinelOne": {
       "detected": "True",
       "version": "1.0.25.312",
       "result": "DFI - Malicious OLE",
       "update": "20190407"
     },
     "F-Prot": {
       "detected": "False",
       "version": "4.7.1.166",
       "result": "NULL",
       "update": "20190412"
     },
     "Jiangmin": {
       "detected": "False",
       "version": "16.0.100",
       "result": "NULL",
       "update": "20190412"
     },
     "Avira": {
       "detected": "False",
       "version": "8.3.3.8",
       "result": "NULL",
       "update": "20190412"
     },
     "MAX": {
       "detected": "False",
       "version": "2018.9.12.1",
       "result": "NULL",
       "update": "20190412"
     },
     "Antiy-AVL": {
       "detected": "False",
       "version": "3.0.0.1",
       "result": "NULL",
       "update": "20190412"
     },
     "Kingsoft": {
       "detected": "False",
       "version": "2013.8.14.323",
       "result": "NULL",
       "update": "20190412"
     },
     "Microsoft": {
       "detected": "True",
       "version": "1.1.15800.1",
       "result": "Trojan:O97M/Sonbokli.A!cl",
       "update": "20190412"
     },
     "Endgame": {
       "detected": "True",
       "version": "3.0.9",
       "result": "malicious (high confidence)",
       "update": "20190403"
     },
     "ViRobot": {
       "detected": "False",
       "version": "2014.3.20.0",
       "result": "NULL",
       "update": "20190412"
     },
     "ZoneAlarm": {
       "detected": "True",
       "version": "1.0",
       "result": "HEUR:Trojan-Downloader.Script.Generic",
       "update": "20190412"
     },
     "Avast-Mobile": {
       "detected": "False",
       "version": "190412-00",
       "result": "NULL",
       "update": "20190412"
     },
     "AhnLab-V3": {
       "detected": "False",
       "version": "3.15.0.23609",
       "result": "NULL",
       "update": "20190412"
     },
     "McAfee": {
       "detected": "False",
       "version": "6.0.6.653",
       "result": "NULL",
       "update": "20190412"
     },
     "TACHYON": {
       "detected": "True",
       "version": "2019-04-12.02",
       "result": "Suspicious/W97M.Obfus.Gen.6",
       "update": "20190412"
     },
     "VBA32": {
       "detected": "False",
       "version": "4.0.0",
       "result": "NULL",
       "update": "20190412"
     },
     "Zoner": {
       "detected": "True",
       "version": "1.0",
       "result": "Probably W97Obfuscated",
       "update": "20190411"
     },
     "Tencent": {
       "detected": "True",
       "version": "1.0.0.1",
       "result": "Heur.Macro.Generic.Gen.h",
       "update": "20190412"
     },
     "Yandex": {
       "detected": "False",
       "version": "5.5.1.3",
       "result": "NULL",
       "update": "20190411"
     },
     "Ikarus": {
       "detected": "True",
       "version": "0.1.5.2",
       "result": "Trojan-Downloader.VBA.Agent",
       "update": "20190412"
     },
     "Fortinet": {
       "detected": "True",
       "version": "5.4.247.0",
       "result": "VBA/Agent.NMG!tr.dldr",
       "update": "20190412"
     },
     "AVG": {
       "detected": "False",
       "version": "18.4.3895.0",
       "result": "NULL",
       "update": "20190412"
     },
     "Panda": {
       "detected": "False",
       "version": "4.6.4.2",
       "result": "NULL",
       "update": "20190412"
     },
     "Qihoo-360": {
       "detected": "False",
       "version": "1.0.0.1120",
       "result": "NULL",
       "update": "20190412"
     }
   },
   "scan_id": "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115-1555071796",
   "sha1": "1daa99558383e50feea9209db93396b43b316c00",
   "resource": "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115",
   "response_code": 1,
   "scan_date": "2019-04-12 12:23:16",
   "permalink": "https://www.virustotal.com/file/9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115/analysis/1555071796/",
   "verbose_msg": "Scan finished, information embedded",
   "total": 60,
   "positives": 16,
   "sha256": "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115",
   "md5": "cc514ad39faa99436978fc5128efae78"
 }'''

querry_ip_response = json.loads(querry_ok)


def querry_status_virustotal_file(resp_json):
    if resp_json['response_code'] == '0':
        print('[!] Invalid sha')
        return False
    else:
        detected_dict = {}
        for index, av_name in enumerate(resp_json['scans']):
        # For each Anti-virus name, find the detected value.
            detected = resp_json['scans'][av_name]['detected']
            # if the above value is true.
            detected_dict["found_positives"] = ("{} / {}".format(resp_json['positives'], resp_json['total']))
            detected_dict["permalink"] = resp_json["permalink"]
            #detected_dict[av_name] = resp_json['scans'][av_name]['result']
            print("ciao")
            print(detected)
            if detected == 'True' or detected == '\n':
                # Print Engines which detect malware.
                # print(f'{av_name} detected Malware!')
                # Add detected engine name and it's result to the detected_dict.
                detected_dict[av_name] = resp_json['scans'][av_name]['result']    
    #print(detected_dict)
    return detected_dict


def text_body(body):
    try:
        for key, val in body.items():
            yield (('{} -> {}').format(key, val))
    except AttributeError:
        pass


boh = text_body(querry_status_virustotal_file(querry_ip_response))

for i in boh:
    print(i)
