import argparse
import os
import pathlib
from cookie_factory import CookieFactory
from cookie_unsigner import CookieUnsigner

parser = argparse.ArgumentParser()
parser.add_argument("--cookie", "-c", type=str, required=True)
parser.add_argument("--words", "-w", action="append", type=str.encode)
parser.add_argument("--wordlist", type=pathlib.Path)

if __name__ == "__main__":
    args = parser.parse_args()
    cookie = CookieFactory(args.cookie)
    unsigner = CookieUnsigner(wordlist=args.words, path=args.wordlist)
    has_unsign = unsigner.unsign(cookie)
    if has_unsign:
        print(unsigner.get_secret_key())



