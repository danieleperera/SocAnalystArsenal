"""
main
install
    install using pip
uninstall
    delete api.json
create_api_json

"""
import json
from pathlib import Path
from argparse import ArgumentParser

NAME = "soc-analyst-arsenal"


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '--uninstall', '-u',
        action='store_true',
        help=f"Remove {NAME} from your system."
    )
    args = parser.parse_args()
    if args.uninstall:
        uninstall()
    else:
        install()
