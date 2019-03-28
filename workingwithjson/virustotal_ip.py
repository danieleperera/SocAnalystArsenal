import json

querry_ok = '''{
  "detected_downloaded_samples": [
    {
      "date": "2019-03-25 07:18:20",
      "positives": 19,
      "total": 55,
      "sha256": "8c223a11049d070a138c8d3c901de1f70ac496621d528747843d9ecda60f7b13"
    },
    {
      "date": "2019-03-25 07:18:18",
      "positives": 19,
      "total": 54,
      "sha256": "07c7817d2ba02351a7c501972e64c59e23334f3b8eb7eeaa41cc33f258cda3b1"
    },
    {
      "date": "2019-03-25 07:14:04",
      "positives": 23,
      "total": 56,
      "sha256": "a89f1ac90904444489ba6f1dd30dfcbe2b17712b6d94f7a8919943254c11c9c6"
    },
    {
      "date": "2019-03-25 07:14:00",
      "positives": 16,
      "total": 53,
      "sha256": "85d7057b2d2f7913909b0f98acecd06023084d293c80e08b145691d581d11844"
    },
    {
      "date": "2019-03-25 07:13:58",
      "positives": 23,
      "total": 57,
      "sha256": "c3be5c208561e59cb7949b3ed48f17db6bb55282d0a18fd56481afbffc6ef0de"
    },
    {
      "date": "2019-03-25 07:09:09",
      "positives": 30,
      "total": 58,
      "sha256": "fa5514b6dbeccbd2acfc4589b5c178524d0b9b24b761e8008f6e00d6486dda34"
    }
  ],
  "response_code": 1,
  "as_owner": "DigitalOcean, LLC",
  "detected_referrer_samples": [
    {
      "positives": 24,
      "total": 59,
      "sha256": "e19eace14ce49cfecbcc0b1cb3fbed0c7da8df06d43408e3c2418c68e0a11f46"
    },
    {
      "positives": 23,
      "total": 57,
      "sha256": "78db65599749a461ae6fe5e4c5812ed35bd2abbbb18144e333ef80b17d153c1c"
    },
    {
      "positives": 24,
      "total": 59,
      "sha256": "aac5739ed9d24047ebd43938cd29b360c63c532d0a0df13e5be58115e8479e1d"
    },
    {
      "positives": 23,
      "total": 60,
      "sha256": "d950a1033a818452a38cc8c26f40d77ac686041f963c7fb84ea6d9f1f70eff79"
    },
    {
      "positives": 23,
      "total": 56,
      "sha256": "8406e4aaa0ecedf4c27c008af12dea6b6caab4925717e540f7c0c8fe8d215bb4"
    },
    {
      "positives": 24,
      "total": 56,
      "sha256": "d8628755a0813e8a6b530ba3429cb9b606716c871e5a251deb1c4c79c99c973d"
    },
    {
      "positives": 25,
      "total": 57,
      "sha256": "85b94c58c4802c6ced9abbc341473d875b8dd7df48f4feff5bc2c03035369dbe"
    }
  ],
  "verbose_msg": "IP address in dataset",
  "continent": "EU",
  "country": "GB",
  "resolutions": [
    {
      "last_resolved": "2018-06-02 11:13:11",
      "hostname": "ouranswer.info"
    }
  ],
  "detected_urls": [
    {
      "url": "http://167.99.81.228/lmaowtf/loligang.arm5",
      "positives": 2,
      "total": 66,
      "scan_date": "2019-03-25 11:06:24"
    },
    {
      "url": "http://167.99.81.228/lmaoWTF/loligang.mpsl",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 07:18:17"
    },
    {
      "url": "http://167.99.81.228/lmaoWTF/loligang.mips",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 07:18:14"
    },
    {
      "url": "http://167.99.81.228/lmaoWTF/loligang.ppc",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 07:14:00"
    },
    {
      "url": "http://167.99.81.228/lmaoWTF/loligang.m68k",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 07:13:56"
    },
    {
      "url": "http://167.99.81.228/lmaoWTF/loligang.spc",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 07:13:54"
    },
    {
      "url": "http://167.99.81.228/lmaoWTF/loligang.arm7",
      "positives": 2,
      "total": 66,
      "scan_date": "2019-03-25 07:09:05"
    },
    {
      "url": "http://167.99.81.228/lmaowtf/loligang.mpsl",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 06:39:00"
    },
    {
      "url": "http://167.99.81.228/lmaowtf/loligang.ppc",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 05:05:04"
    },
    {
      "url": "http://167.99.81.228/lmaowtf/loligang.spc",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 05:04:03"
    },
    {
      "url": "http://167.99.81.228/lmaowtf/loligang.arm7",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 05:03:06"
    },
    {
      "url": "http://167.99.81.228/lmaowtf/loligang.x86",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 05:03:00"
    },
    {
      "url": "http://167.99.81.228/lmaowtf/loligang.arm6",
      "positives": 1,
      "total": 66,
      "scan_date": "2019-03-25 05:02:02"
    }
  ],
  "detected_communicating_samples": [
    {
      "date": "2019-01-08 07:15:59",
      "positives": 24,
      "total": 71,
      "sha256": "e19eace14ce49cfecbcc0b1cb3fbed0c7da8df06d43408e3c2418c68e0a11f46"
    },
    {
      "date": "2019-01-08 07:36:34",
      "positives": 24,
      "total": 71,
      "sha256": "aac5739ed9d24047ebd43938cd29b360c63c532d0a0df13e5be58115e8479e1d"
    },
    {
      "date": "2019-01-07 12:51:23",
      "positives": 19,
      "total": 70,
      "sha256": "d950a1033a818452a38cc8c26f40d77ac686041f963c7fb84ea6d9f1f70eff79"
    }
  ],
  "undetected_communicating_samples": [],
  "asn": 14061,
  "network": "167.99.0.0/16"
}'''

querry_bad = '''{
  "response_code": -1,
  "verbose_msg": "Invalid IP address"
    }'''

querry_ip_response = json.loads(querry_ok)



def querry_status_virustotal_ip(positions):
    if positions['response_code'] == -1:
        print('[!] No result on virustotal')
        return False
    else:
        simple_dict = {}
        for index, item in enumerate(positions['detected_downloaded_samples']):
            simple_dict[f"detected_malicious_downloaded_samples_{index}_sha256"] = item['sha256']
            simple_dict[f"detected_file_score_{index}"] = str(item['positives'])+'/'+str(item['total'])
        for index, item in enumerate(positions['detected_urls']):
            simple_dict[f"detected_urls_{index}"] = item['url']
            simple_dict[f"detected_urls_score_{index}"] = str(item['positives'])+'/'+str(item['total'])
        print(simple_dict)
        return simple_dict


querry_status_virustotal_ip(querry_ip_response)