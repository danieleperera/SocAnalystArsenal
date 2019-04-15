info = {'attackers': {
        '124.164.251.179',
        '179.251.164.124.adsl-pool.sx.cn'},
        'victims': '10.10.2.140',
        'context': 'http GET 46.20.95.185'}


def text_header(head):
    test = '''### Attackers -> {}
### Victims   -> {}
### Context   -> {}'''.format(
                head.get("attackers", "Not found!"),
                head.get("victims", "Not found!"),
                head.get("context", "Not found!"))
    print(test)
    return test


text_header(info)