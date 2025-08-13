import hashlib
import typing
import base64
import hmac
from urllib import parse
import enum
import abc

class CookieKind(enum.Enum):
    EXPRESS_SESSION = "express-session"

class Cookie(abc.ABC):
    @abc.abstractmethod
    def parse_cookie(self) -> None:
        ...

    @abc.abstractmethod
    def unsign(self, wordlist: list[bytes]) -> bool:
        ...

    @abc.abstractmethod
    def get_secret_key(self) -> typing.Optional[str]:
        ...

class ExpressSessionCookie(Cookie):
    # https://github.com/expressjs/session/blob/v1.18.2/index.js#L664
    PREFIX = "s:"
    # https://github.com/tj/node-cookie-signature/blob/master/index.js#L19
    SEPARATOR = "."

    def __init__(self, cookie: str):
        self.raw_cookie = cookie
        self.retrieved_secret_key: typing.Optional[str] = None
        self.cookie_value: typing.Optional[bytes] = None
        self.cookie_signature: typing.Optional[bytes] = None

    def parse_cookie(self):
        cookie = parse.unquote(self.raw_cookie)
        cookie_prefix_stripped = cookie.strip(self.PREFIX)
        cookie_value, cookie_signature = cookie_prefix_stripped.split(self.SEPARATOR)
        self.cookie_value = cookie_value.encode()
        self.cookie_signature = cookie_signature

    def unsign(self, wordlist: list[bytes]) -> bool:
        self.parse_cookie()
        for key in wordlist:
            key_without_crlf = key.strip(b"\r").strip(b"\n")
            digest = hmac.new(key_without_crlf, self.cookie_value, digestmod=hashlib.sha256).digest()
            has_unsign = base64.b64encode(digest).decode().split("=")[0] == self.cookie_signature
            if has_unsign:
                self.retrieved_secret_key = key_without_crlf.decode()
                return has_unsign
        return False

    def get_secret_key(self) -> typing.Optional[str]:
        return self.retrieved_secret_key
        
class CookieFactory:
    cookie: dict[str, type[Cookie]] = {"express-session": ExpressSessionCookie}

    @classmethod
    def get_factory(cls, kind: str):
        return cls.cookie[kind]


