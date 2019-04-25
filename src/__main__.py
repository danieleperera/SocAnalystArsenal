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

    options = parser.parse_args()

    # Default to webscapper
    if options.boolean_switch_mode:
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
                    query.verbose_mode(options.bool_vb))

            except exceptions.StaleElementReferenceException:
                print(iconError, end='')
                print(" Error Occured... Entering manual mode")
                query.manual_mode_ip(
                    options.ip,
                    query.verbose_mode(options.bool_vb),
                    options.sha_sum)
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
                options.ip,
                query.verbose_mode(options.bool_vb),
                options.sha_sum)

    else:
        # User entered option to get manual mode
        print(iconOK, end='')
        print(" Entering manual mode")
        # check if argpase values are null
        query.manual_mode_ip(
            options.ip,
            query.verbose_mode(options.bool_vb),
            options.sha_sum)


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
    
    for query_string, type_query in query.check_query_type(info['attackers']):
        print(query_string, type_query)
        print(
            '\n ======= Creating ticket for {} =======\n\n'.format(
                    query_string))
        query.virustotal_query(
            query_string,
            type_query,
            verbosity_check)
        # query.progressbar_ip(ip_addresses)
        query.iphub_query(
            query_string,
            type_query,
            verbosity_check)
        # query.progressbar_ip(ip_addresses)
        query.getipintel_query(
            query_string,
            type_query,
            verbosity_check)
        # query.progressbar_ip(ip_addresses)
        query.shodan_query(
            query_string,
            type_query,
            verbosity_check)

        # query.progressbar_ip(ip_addresses)
        query.threatcrowd_query(
            query_string,
            type_query,
            verbosity_check)

        # query.progressbar_ip(ip_addresses)
        query.hybrid_query(
            query_string,
            type_query,
            verbosity_check)

        # query.progressbar_ip(ip_addresses)
        query.apility_query(
            query_string,
            type_query,
            verbosity_check)

        # query.progressbar_ip(ip_addresses)
        query.abuseipdb_query(
            query_string,
            type_query,
            verbosity_check)
        # query.progressbar_ip(ip_addresses)
        query.urlhause_query(
            query_string,
            type_query,
            verbosity_check)

        # query.progressbar_ip(ip_addresses)
        query.threatminer_query(
            query_string,
            type_query,
            verbosity_check)

        query.urlscan_query(
            query_string,
            type_query,
            verbosity_check)

                # query.progressbar_ip(ip_addresses)

        toaster.show_toast("""Ticket copied to clipboard""", duration=10)


if __name__ == '__main__':
    try:
        #main()
        collector(True)
    except KeyboardInterrupt:
        print('deleting tmp files')
        print(iconOK, end='')
        print(" Exit")
        sys.exit()
    # collector(False)
