# -*- coding: utf-8 -*-
# -*- style: PEP8 -*-
import query
import os
from win10toast import ToastNotifier
from __init__ import SRC
from colorama import Fore, init
import argparse
from selenium.common import exceptions
import sys
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
    
    for data, type_data in query.check_domain_or_ip(info['attackers']):
        for element in data:
            print(
                '\n ======= Creating ticket for {} =======\n\n'.format(
                    element))
            if sha_sum_list is None:

                virustotal = query.virustotal_query(
                                                    element,
                                                    type_data,
                                                    verbosity_check)
                # query.progressbar_ip(ip_addresses)

                iphub = query.iphub_query(
                                            element,
                                            type_data,
                                            verbosity_check)
                # query.progressbar_ip(ip_addresses)


                getipintel = query.getipintel_query(
                                                    element,
                                                    type_data,
                                                    verbosity_check)
                # query.progressbar_ip(ip_addresses)

                shodan = query.shodan_query(
                    element,
                    type_data,
                    verbosity_check)

                # query.progressbar_ip(ip_addresses)


                threatcrowd = query.threatcrowd_query(
                    element,
                    type_data,
                    verbosity_check)

                # query.progressbar_ip(ip_addresses)



                hybrid = query.hybrid_query(
                    element,
                    type_data,
                    verbosity_check)

                # query.progressbar_ip(ip_addresses)


                apility = query.apility_query(
                    element,
                    type_data,
                    verbosity_check)

                # query.progressbar_ip(ip_addresses)


                abuseipdb = query.abuseipdb_query(
                    element,
                    type_data,
                    verbosity_check)
                # query.progressbar_ip(ip_addresses)



                urlhause = query.urlhause_query(
                    element,
                    type_data,
                    verbosity_check)

                # query.progressbar_ip(ip_addresses)

                tmp.write(header_spread)
                for i in query.text_body(urlhause):
                    tmp.write(i)

                threatminer = query.threatminer_query(
                    element,
                    type_data,
                    verbosity_check)

                # query.progressbar_ip(ip_addresses)

                for i in query.text_body(threatminer):
                    tmp.write(i)

                urlscan = query.urlscan_query(
                    element,
                    type_data,
                    verbosity_check)

                # query.progressbar_ip(ip_addresses)

                tmp.write(header_info)
                for i in query.text_body(urlscan):
                    tmp.write(i)

        toaster.show_toast("""Ticket copied to clipboard""", duration=10)
        # ===================== ************* ===============================
        # ---------------------- END IP addresses -----------------------
        # ===================== ************* ===============================

# ======================= ************* ===============================
# -------------- Validating information purposes ----------------------
# ======================== ************* ==============================


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('deleting tmp files')
        print(iconOK, end='')
        print(" Exit")
        sys.exit()
    # collector(False)
