from cookie_unsigner import CookieUnsigner
import argparse
from main import parser
from cookie_factory import CookieFactory


def test_we_can_successfully_retrieve_django_secret_key():
    args = parser.parse_args(
        [
            "--kind",
            "django",
            "--cookie",
            "hello:KXqvql0eQjIXpwtXbGGGF2qhuX6I-dtk2XhUGnrNPyw",
            "-w",
            "django-insecure-+$$2zufu5dcjz)=ny5+zp+avsprq78oyzl&ek1aw&hl@)m(db%",
        ]
    )
    cookie = CookieFactory.get_cookie(kind=args.kind, cookie=args.cookie)
    unsigner = CookieUnsigner(wordlist=args.words)
    has_unsign = unsigner.unsign(cookie)
    assert has_unsign
    secret_key = unsigner.get_secret_key()
    assert (
        secret_key
        == "django-insecure-+$$2zufu5dcjz)=ny5+zp+avsprq78oyzl&ek1aw&hl@)m(db%"
    )


def test_we_can_successfully_retrieve_django_secret_key_using_file_wordlist(
    tmpdir,
):
    wordlist_path = tmpdir.mkdir("wordlist").join("wordlist.txt")
    wordlist_path.write(
        b"secret_key\nsuper_secret_key\nmy-other-secret\ndjango-insecure-+$$2zufu5dcjz)=ny5+zp+avsprq78oyzl&ek1aw&hl@)m(db%"
    )
    args = parser.parse_args(
        [
            "--kind",
            "django",
            "--cookie",
            "hello:KXqvql0eQjIXpwtXbGGGF2qhuX6I-dtk2XhUGnrNPyw",
            "--wordlist",
            str(wordlist_path),
        ]
    )
    cookie = CookieFactory.get_cookie(kind=args.kind, cookie=args.cookie)
    unsigner = CookieUnsigner(path=args.wordlist)
    has_unsign = unsigner.unsign(cookie)
    assert has_unsign
    secret_key = unsigner.get_secret_key()
    assert (
        secret_key
        == "django-insecure-+$$2zufu5dcjz)=ny5+zp+avsprq78oyzl&ek1aw&hl@)m(db%"
    )


def test_we_dont_yield_false_positive(tmpdir):
    wordlist_path = tmpdir.mkdir("wordlist").join("wordlist.txt")
    wordlist_path.write(
        b"secret_key\nsuper_secret_key\nkeyboard cat\nmy-other-secret-key\nmy-other-secret\ndjango-insecure-+$$2zufu5dcjz)=ny5+zp+avsprq78oyzl&ek1aw&hl@)m(db%"
    )
    args = parser.parse_args(
        [
            "--kind",
            "django",
            "--cookie",
            "hello:nMgAAEvue0fs5wPVYjxxtIN92UJ2SD72NMYICclOsW0",
            "--wordlist",
            str(wordlist_path),
        ]
    )
    cookie = CookieFactory.get_cookie(kind=args.kind, cookie=args.cookie)
    unsigner = CookieUnsigner(path=args.wordlist)
    has_unsign = unsigner.unsign(cookie)
    assert not has_unsign
