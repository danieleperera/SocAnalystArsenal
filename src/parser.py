import argparse

class Foo:
    def __init__(self):
        self.parser = ArgumentParser()
        self.parser.add_argument('-f', '--foo', default=False, action='store_true', help='foo or not?')
        self.parser.add_argument('-b', '--bar', default=0, action='store', help='set the bar')
        self.parser.parse_args(namespace=self)