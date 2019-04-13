import argparse


print("Il tool automatizzato per cercare gli ip malevoli non esiste, inserisci manualmente gli ip")
parser = argparse.ArgumentParser()
parser.add_argument("--ip", dest="ip", help="somehelp bla bla", default="")
addr = parser.parse_args()
if addr.ip == '':
    ip = input('Please input ip:')
    print(ip)

    attackers = {}
    attackers['attackers'] = "\n".join(ip)
    print(attackers['attackers'])
else:
    print(addr.ip)
    attackers = {}
    attackers['attackers'] = "\n".join(addr.ip)
    print(attackers)