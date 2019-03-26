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

print(json.loads(testing))