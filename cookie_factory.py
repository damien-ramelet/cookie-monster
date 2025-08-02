import hashlib
import typing
import base64
import hmac

class CookieFactory:
    def __init__(self, cookie: str):
        self.raw_cookie = cookie
        self.retrieved_secret_key: typing.Optional[str] = None

    def unsign(self, wordlist: list[bytes]) -> bool:
        cookie_value, cookie_signature = self.raw_cookie.split(".")
        bytes_value = cookie_value.encode()
        for key in wordlist:
            key_without_crlf = key.strip(b"\r").strip(b"\n")
            digest = hmac.new(key_without_crlf, bytes_value, digestmod=hashlib.sha256).digest()
            has_unsign = base64.b64encode(digest).decode().split("=")[0] == cookie_signature
            if has_unsign:
                self.retrieved_secret_key = key_without_crlf.decode()
                return has_unsign
        return False

    def get_secret_key(self) -> typing.Optional[str]:
        return self.retrieved_secret_key
        
