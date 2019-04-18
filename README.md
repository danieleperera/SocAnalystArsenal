# Soc-L1-Automation

[![N|Solid](https://camo.githubusercontent.com/5392ad6fb7875a2520001270f08309896b6cb25d/687474703a2f2f466f7254686542616467652e636f6d2f696d616765732f6261646765732f6d6164652d776974682d707974686f6e2e737667)](https://www.python.org/)

[![Build Status](https://img.shields.io/badge/Version-v0.0.1-brightgreen.svg)](https://shields.io/) [![Build Status](https://img.shields.io/badge/Status-Building-red.svg)](https://shields.io/) [![Build Status](https://img.shields.io/badge/Platform-windows10-blue.svg)](https://shields.io/)

[![Build Status](https://img.shields.io/badge/API-urlscan.io-lightgrey.svg)](https://urlscan.io/) [![Build Status](https://img.shields.io/badge/API-abuseipdb-lightgrey.svg)](https://www.abuseipdb.com/) [![Build Status](https://img.shields.io/badge/API-urlhaus-lightgrey.svg)](https://urlhaus.abuse.ch/) [![Build Status](https://img.shields.io/badge/API-shodan-lightgrey.svg)](https://www.virustotal.com/gui/home/upload) [![Build Status](https://img.shields.io/badge/API-apility.io-lightgrey.svg)](https://www.virustotal.com/gui/home/upload) [![Build Status](https://img.shields.io/badge/API-hybrid-lightgrey.svg)](https://www.virustotal.com/gui/home/upload) [![Build Status](https://img.shields.io/badge/API-malshare-lightgrey.svg)](https://www.virustotal.com/gui/home/upload) [![Build Status](https://img.shields.io/badge/API-threatcrowd-lightgrey.svg)](https://www.virustotal.com/gui/home/upload) [![Build Status](https://img.shields.io/badge/API-threatminer-lightgrey.svg)](https://www.virustotal.com/gui/home/upload)


This tool is used to give a quick structure to a SOC level 1 ticket. I used Selenium to gather infomation regarding an attack from our company's SIEM/IDS then I use that information with APIs from urlscan.io, abuseipdb, urlhaus, virustotal to collect more information by parsing json files and creating a basic structure that will be copied to the clipboard once done. While this tool is running the L1 Soc User can save time because he don't need to copy and paste information from the siem to other threat analysing websites and then coping that information to a ticket so he can do more advanced analysis of a threat and the quality of a ticket will increase rapidly.
  
![asdasdfiledacaricare](https://user-images.githubusercontent.com/45230107/55170057-2decdf80-5176-11e9-889c-a4f67fdb49f8.gif)


## ToDo
  - ~~create a ticket from all the information gathered and copy it to clipboard and give notification to user~~
  - ~~add some colors~~
  - ~~collect IOCs from virustotal json~~
  - open to new enhancements
  - ~~timeout option for abuseipdb and other requests~~
  - do more testing with siem
  - do more testing in manual mode
  - try to integrate semi-manual mode
  - if no results found don't notify

## Usage
```
          _______
         /      /,      ;___________________;
        /      //       ; Soc-L1-Automation ;
       /______//        ;-------------------;
      (______(/             danieleperera
      
usage: Soc-L1-Automation [-h] [-m] [--version] [--ip IP [IP ...]] [--sha SHA_SUM] [-v]

optional arguments:
  -h, --help         show this help message and exit
  -m, --manual-mode  To enter manual mode use this option
  --version          show program's version number and exit
  --ip IP [IP ...]   give a list of potential malicious ip addresses
  --sha SHA_SUM      Add SHA values to a list
  -v, --verbose      Use this flag to get full data from APIs
```
  
## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

| Api         | Description                                                | Auth    |
|-------------|------------------------------------------------------------|---------|
| virustotal  | Check Whois information for IP address/Domain              | `apikey`|
| getipintel  | Check check if the IP is a proxy or spoofed                | `apikey`|
| shodan      | Check information about host and see if it was compromised | `apikey`|
| apility.io  | Check reputation and activity through time                 | `apikey`|
| hybrid      | Check association with malware                             | `apikey`|
| malshare    | Check IP address/Domain was used to spread malware         | `apikey`|
| urlhause    | Check IP address/Domain was used to spread malware         | none    |
| threatcrowd | Check Current status                                       | `apikey`|
| abuseipdb   | Check if it's blacklisted                                  | none    |
| urlscan.io  | Check further more information                             | none    |
| threatminer | Check further more information                             | none    |

### Prerequisites

You need python version > 3.7

```
 python --version
```

### Installing

Additional details are coming soon.

Additional details are coming soon.

```
Give the example
```

Additional details are coming soon.

```
until finished
```

Additional details are coming soon.

## Running the tests

Additional details are coming soon.

### Break down into end to end tests

Additional details are coming soon.

```
Give an example
```

### And coding style tests

Additional details are coming soon.

```
Give an example
```

## Deployment

This project can be deployed on Cloud too. More Additional details are coming soon.

## Built With

* [Python](https://www.python.org/) - 100%

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/danieleperera/clean_breach/tags). 

## Author

* **Daniele Perera** - [Mr. Px0r](https://github.com/danieleperera)

See also the list of [contributors](https://github.com/danieleperera/clean_breach/graphs/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details







