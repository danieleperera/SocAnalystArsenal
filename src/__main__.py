# -*- coding: utf-8 -*-
# -*- style: PEP8 -*-
import query
import os
import tempfile
import pyperclip
from win10toast import ToastNotifier
from __init__ import SRC
from colorama import Fore, init
import argparse
from selenium.common import exceptions
# icons
iconOK = (Fore.GREEN + '[ok]')
iconNone = (Fore.YELLOW + '[*]')
iconError = (Fore.RED + '[!]')
init(autoreset=True)
# python .\__main__.py -m --ip 68.183.65.178 --sha
# 33f810fd192ee4828b331fcbb11a33a567c53ff2bbf24234c48f4a7d68b73f73 -v


def main():
    """
    Documentation for main.

    It prints the banner and uses argparse to get data from user.
    If no option is given, it defaults to use webscapper.
    """
    print(Fore.CYAN + query.print_banner())

    parser = argparse.ArgumentParser()

    parser.add_argument('-m', '--manual-mode', action='store_false',
                        default=True,
                        dest='boolean_switch_mode',
                        help='To enter manual mode use this option')

    parser.add_argument('--version', action='version',
                        version='%(prog)s 1.0.0')

    parser.add_argument('--ip', nargs='+', dest='ip',
                        help='give a list of potential malicious ip addresses')

    parser.add_argument('--sha', action='append', dest='sha_sum',
                        default=[],
                        help='Add SHA values to a list')

    parser.add_argument('-v', '--verbose', action='store_false',
                        default=True,
                        dest='bool_vb',
                        help='Use this flag to get full data from APIs')

    results = parser.parse_args()

    # Default to webscapper
    if results.boolean_switch_mode:
        # check if file webscapper exsist to get data from it
        Webscapperpath = os.path.join(SRC, "webscapper_1.py")
        exists = os.path.isfile(Webscapperpath)
        if exists:
            import webscapper
            try:
                # try to get data from webscapper
                # if error occured jump to manual mode
                collector(
                    webscapper.get_info(),
                    query.verbose_mode(results.bool_vb))

            except exceptions.StaleElementReferenceException:
                print(iconError, end='')
                print(" Error Occured... Entering manual mode")
                query.manual_mode_ip(
                    results.ip,
                    query.verbose_mode(results.bool_vb),
                    results.sha_sum)
            # Testing purposes
            # info = {'attackers': {'124.164.251.179',
            #                       '179.251.164.124.adsl-pool.sx.cn'},
            #        'victims': '10.10.2.140',
            #        'context': 'http GET 46.20.95.185'}
            #
        else:
            # Default to webscapper but webscapper isn't in path
            # Enter manual mode
            print(iconError, end='')
            print(""" It seems you don't have webscapper on path...
Entering manual mode""")
            query.manual_mode_ip(
                results.ip,
                query.verbose_mode(results.bool_vb),
                results.sha_sum)

    else:
        # User entered option to get manual mode
        print(iconOK, end='')
        print(" Entering manual mode")
        # check if argpase values are null
        query.manual_mode_ip(
            results.ip,
            query.verbose_mode(results.bool_vb),
            results.sha_sum)


def collector(info: dict, verbosity_check: bool, sha_sum_list: list = None):
    """
    Documentation for collector.
    Creates a tmp file and pass the dict to other functions,
    copy data from those functions to the tmp file,
    once done delete the tmp file and gives a desktop notification popup.

    param
        info: dict -- This is a dictionary variable.

    example::

    ```
     info = {'attackers': {'124.164.251.179',
                           '179.251.164.124.adsl-pool.sx.cn'},
            'victims': '10.10.2.140',
            'context': 'http GET 46.20.95.185'}
    ```
    """
    # --- Notification ---
    toaster = ToastNotifier()
    # --- Clipboard / tmp file ---
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'r+', encoding='utf-8') as tmp:
            #  ===================== ************* ===========================
            # ------ IP addresses are getting worked here --------------------
            # ===================== ************* ============================
            # ip_addresses = info['attackers']
            tmp.write(query.text_header(info))
            for data, type_data in query.check_domain_or_ip(info['attackers']):
                for element in data:
                    print('Creating ticket for {}\n\n'.format(element))
                    if sha_sum_list is None:
                        virustotal = query.virustotal_query(
                                                            element,
                                                            type_data,
                                                            verbosity_check)
                        # query.progressbar_ip(ip_addresses)
                        header_whois = (
                            '\nWhois Information ' + element + '\n')
                        tmp.write(header_whois)
                        tableContent_virustotal = query.text_body_table(
                            virustotal)
                        tmp.write('{}'.format(query.printTable(
                            tableContent_virustotal)))

                        iphub = query.iphub_query(
                                                    element,
                                                    type_data,
                                                    verbosity_check)
                        # query.progressbar_ip(ip_addresses)
                        header_spoofed_IPhub = (
                            '\n\nVPN/Proxy/Tor Information IPhub '
                            + element + '\n')
                        tmp.write(header_spoofed_IPhub)
                        for i in query.text_body(iphub):
                            tmp.write(i)

                        getipintel = query.getipintel_query(
                                                            element,
                                                            type_data,
                                                            verbosity_check)
                        # query.progressbar_ip(ip_addresses)
                        header_spoofed_getipintel = (
                            '\n\nVPN/Proxy/Tor Information GetIPintel '
                            + element + '\n')
                        tmp.write(header_spoofed_getipintel)
                        for i in query.text_body(getipintel):
                            tmp.write(i)

                        shodan = query.shodan_query(
                            element,
                            type_data,
                            verbosity_check)

                        # query.progressbar_ip(ip_addresses)
                        header_compromised = (
                            '\n\nCompromised Information '
                            + element + '\n')
                        tmp.write(header_compromised)
                        tableContent_shodan = query.text_body_table(shodan)
                        tmp.write('{}'.format(query.printTable(
                            tableContent_shodan)))

                        threatcrowd = query.threatcrowd_query(
                            element,
                            type_data,
                            verbosity_check)

                        # query.progressbar_ip(ip_addresses)
                        header_status = (
                            '\n\nCurrent status information '
                            + element + '\n')
                        tmp.write(header_status)
                        for i in query.text_body(threatcrowd):
                            tmp.write(i)

                        hybrid = query.hybrid_query(
                            element,
                            type_data,
                            verbosity_check)

                        # query.progressbar_ip(ip_addresses)
                        header_association = (
                            '\n\nAssociation with malware information '
                            + element + '\n')
                        tmp.write(header_association)
                        table_association = query.printTable_row(hybrid)
                        tmp.write('{}'.format(table_association))

                        apility = query.apility_query(
                            element,
                            type_data,
                            verbosity_check)

                        # query.progressbar_ip(ip_addresses)
                        header_reputation = (
                            '\n\nReputation and activity through time '
                            + element + '\n')
                        tmp.write(header_reputation)
                        table_reputation = query.printTable_row(apility)
                        tmp.write('{}'.format(table_reputation))

                        abuseipdb = query.abuseipdb_query(
                            element,
                            type_data,
                            verbosity_check)
                        # query.progressbar_ip(ip_addresses)
                        header_blacklisted = (
                            '\n\nBlacklisted Data '
                            + element + '\n')
                        tmp.write(header_blacklisted)
                        for i in query.text_body(abuseipdb):
                            tmp.write(i)

                        urlhause = query.urlhause_query(
                            element,
                            type_data,
                            verbosity_check)

                        # query.progressbar_ip(ip_addresses)
                        header_spread = (
                            '\n\nIP address/Domain was used to spread malware '
                            + element + '\n')
                        tmp.write(header_spread)
                        for i in query.text_body(urlhause):
                            tmp.write(i)

                        threatminer = query.threatminer_query(
                            element,
                            type_data,
                            verbosity_check)

                        # query.progressbar_ip(ip_addresses)
                        header_info2 = (
                            '\n\nMore information '
                            + element + '\n')
                        tmp.write(header_info2)
                        for i in query.text_body(threatminer):
                            tmp.write(i)

                        urlscan = query.urlscan_query(
                            element,
                            type_data,
                            verbosity_check)

                        # query.progressbar_ip(ip_addresses)
                        header_info = (
                            '\n\nMore information '
                            + element + '\n')
                        tmp.write(header_info)
                        for i in query.text_body(urlscan):
                            tmp.write(i)
        # ===================== ************* ===============================
        # ---------------------- END IP addresses -----------------------
        # ===================== ************* ===============================
            tmp.seek(0)
            content = tmp.read()
            if content == '':
                print('\n' + iconError + ' No ticket was copied to clipboard')
                print("\n\nRemoving tmp files... Please wait")
            else:
                print('\n' + iconOK, end='')
                print(' Ticket was copied to clipboard successfully')
                print("\n\nRemoving tmp files... Please wait")
                pyperclip.copy(content)
        toaster.show_toast("""Ticket copied to clipboard""", duration=10)
    finally:
        # print(path)
        os.remove(path)
# ======================= ************* ===============================
# -------------- Validating information purposes ----------------------
# ======================== ************* ==============================


if __name__ == '__main__':
    main()
    # collector(False)
