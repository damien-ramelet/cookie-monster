import argparse
import os
import pathlib
from cookie_factory import CookieFactory, CookieKind
from cookie_unsigner import CookieUnsigner

parser = argparse.ArgumentParser()
parser.add_argument("--kind", "-k", choices=[kind.value for kind in CookieKind], required=True)
parser.add_argument("--cookie", "-c", type=str, required=True)
parser.add_argument("--words", "-w", action="append", type=str.encode)
parser.add_argument("--wordlist", type=pathlib.Path)

if __name__ == "__main__":
    args = parser.parse_args()
    factory = CookieFactory.get_factory(kind=args.kind)
    cookie = factory(cookie=args.cookie)
    unsigner = CookieUnsigner(wordlist=args.words, path=args.wordlist)
    has_unsign = unsigner.unsign(cookie)
    if has_unsign:
        print(unsigner.get_secret_key())



