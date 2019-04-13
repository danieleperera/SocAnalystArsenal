import json

testing = '''{
    "query_status": "ok",
    "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/host\/178.128.78.235\/",
    "host": "178.128.78.235",
    "firstseen": "2019-03-25 09:55:01 UTC",
    "url_count": "11",
    "blacklists": {
        "spamhaus_dbl": "not listed",
        "surbl": "not listed"
    },
    "urls": [
        {
            "id": "165356",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165356\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.x86",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:39 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165355",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165355\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.spc",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:36 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165354",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165354\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.sh4",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:33 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165353",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165353\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.ppc",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:29 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165352",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165352\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.mpsl",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:27 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165351",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165351\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.mips",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:24 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165350",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165350\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.m68k",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:20 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165349",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165349\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.arm7",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:17 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165348",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165348\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.arm6",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:12 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165346",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165346\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.arm5",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:07 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        },
        {
            "id": "165345",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/165345\/",
            "url": "http:\/\/178.128.78.235\/bins\/Solar.arm",
            "url_status": "online",
            "date_added": "2019-03-25 09:55:04 UTC",
            "threat": "malware_download",
            "reporter": "0xrb",
            "larted": "true",
            "takedown_time_seconds": null,
            "tags": [
                "elf",
                "mirai"
            ]
        }
    ]
}
'''
testing2 = '''{
    "query_status": "http_post_expected",
    "id": "105821",
    "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/105821\/",
    "url": "http:\/\/sskymedia.com\/VMYB-ht_JAQo-gi\/INV\/99401FORPO\/20673114777\/US\/Outstanding-Invoices\/",
    "url_status": "online",
    "host": "sskymedia.com",
    "date_added": "2019-01-19 01:33:26 UTC",
    "threat": "malware_download",
    "blacklists": {
        "gsb": "not listed",
        "spamhaus_dbl": "abused_legit_malware",
        "surbl": "listed"
    },
    "reporter": "Cryptolaemus1",
    "larted": "true",
    "takedown_time_seconds": null,
    "tags": [
        "emotet",
        "epoch2",
        "heodo"
    ],
    "payloads": [
      {
          "firstseen": "2019-01-19",
          "filename": "5616769081079106.doc",
          "content_type": "doc",
          "response_size": "179664",
          "response_md5": "fedfa8ad9ee7846b88c5da79b32f6551",
          "response_sha256": "dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403",
          "urlhaus_download": "https:\/\/urlhaus-api.abuse.ch\/v1\/download\/dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403\/",
          "signature": null,
          "virustotal": {
              "result": "16 \/ 58",
              "percent": "27.59",
              "link": "https:\/\/www.virustotal.com\/file\/dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403\/analysis\/1547871259\/"
          }
      },
      {
          "firstseen": "2019-01-19",
          "filename": "ATT932454259403171471.doc",
          "content_type": "doc",
          "response_size": "174928",
          "response_md5": "12c8aec5766ac3e6f26f2505e2f4a8f2",
          "response_sha256": "01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b00",
          "urlhaus_download": "https:\/\/urlhaus-api.abuse.ch\/v1\/download\/01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b00\/",
          "signature": "Heodo",
          "virustotal": null
      }
    ]
}
'''

def querry_status_urlhause_ip(positions):
    if positions['query_status'] != 'ok':
        print('[!] No result on urlhause')
    else:
        response_querry_url_information = {
        "urlhaus_reference" : positions['urls'][0]['urlhaus_reference'],
        "threat" : positions['urls'][0]['threat'],
        "url_status" : positions['urls'][0]['url_status'],
        "tags" : positions['urls'][0]['tags']
    }
        return response_querry_url_information

querry_host_url_response = json.loads(testing2)

querry_status_urlhause_ip(querry_host_url_response)
    

    