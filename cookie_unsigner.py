from cookie_factory import CookieFactory
import pathlib
import typing

class CookieUnsigner:
    def __init__(self, wordlist: typing.Optional[list[bytes]] = None, path: typing.Optional[pathlib.Path] = None):
        self.signed_cookie: typing.Optional[CookieFactory] = None
        self.wordlist: list[bytes]
        if wordlist is not None:
            self.wordlist = wordlist
        if path is not None:
            with path.open("rb") as f:
                self.wordlist = f.readlines()

    def unsign(self, signed_cookie: CookieFactory) -> bool:
        self.signed_cookie = signed_cookie
        return self.signed_cookie.unsign(self.wordlist)

    def get_secret_key(self) -> typing.Optional[str]:
        if self.signed_cookie is None:
            raise ValueError("You need to run the `unsign` command first")
        return self.signed_cookie.get_secret_key()
