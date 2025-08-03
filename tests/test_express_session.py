from cookie_unsigner import CookieUnsigner
import argparse
from main import parser
from cookie_factory import CookieFactory

def test_we_can_successfully_retrieve_express_session_cookie_secret_key():
    args = parser.parse_args(["--cookie", "s:edfa9614-4121-483e-9896-afded4356b45.4+c7tI8qYd9bpiOfCRhg6sxwSuK8RLOyoQf6MSo1Rww", "-w", "keyboard cat"])
    cookie = CookieFactory(args.cookie)
    unsigner = CookieUnsigner(wordlist=args.words)
    has_unsign = unsigner.unsign(cookie)
    assert has_unsign
    secret_key = unsigner.get_secret_key()
    assert secret_key == "keyboard cat"

def test_we_can_successfully_retrieve_express_session_cookie_secret_key_using_wordlist():
    args = parser.parse_args(["--cookie", "s:089ef98d-191a-43d0-a262-e0c78b34ce5c.WlvcIjHCE2XhlfFDeveCG4fo9jPFqbNFEkejBlYiKGo", "-w", "secret_key", "-w", "super_secret_key", "-w", "keyboard cat"])
    cookie = CookieFactory(args.cookie)
    unsigner = CookieUnsigner(wordlist=args.words)
    has_unsign = unsigner.unsign(cookie)
    assert has_unsign
    secret_key = unsigner.get_secret_key()
    assert secret_key == "secret_key"

def test_we_can_successfully_retrieve_express_session_cookie_secret_key_using_file_wordlist(tmpdir):
    wordlist_path = tmpdir.mkdir("wordlist").join("wordlist.txt")
    wordlist_path.write(b"secret_key\nsuper_secret_key\nkeyboard cat")
    args = parser.parse_args(["--cookie", "s:0586e564-abdd-4759-b733-e3a4a689deed.PLreZm2d9TbGOXVHSA7Nubi/5hv1Tnok5LMjqrWVEzA", "--wordlist", str(wordlist_path)])
    cookie = CookieFactory(args.cookie)
    unsigner = CookieUnsigner(path=args.wordlist)
    has_unsign = unsigner.unsign(cookie)
    assert has_unsign
    secret_key = unsigner.get_secret_key()
    assert secret_key == "super_secret_key"

def test_we_dont_yield_false_positive(tmpdir):
    wordlist_path = tmpdir.mkdir("wordlist").join("wordlist.txt")
    wordlist_path.write(b"secret_key\nsuper_secret_key\nkeyboard cat")
    args = parser.parse_args(["--cookie", "s:96ce5dff-0ce0-4e0b-adf5-f89d3d1073e4.Wr8bI5AFn9t3vUi+LSFQ7yo+XOhABAmdrHH6o4Hl9hg", "--wordlist", str(wordlist_path)])
    cookie = CookieFactory(args.cookie)
    unsigner = CookieUnsigner(path=args.wordlist)
    has_unsign = unsigner.unsign(cookie)
    assert not has_unsign

def test_we_can_past_the_all_thing_and_run_successfully():
    args = parser.parse_args(["--cookie", "s:9b8566a8-7808-4f20-ab8e-2ca77dfbc8df.bcfvx44eJ6FZF3afR0UVu55WeN4OijNrzrZtPOsU62w", "-w", "keyboard cat"])
    cookie = CookieFactory(args.cookie)
    unsigner = CookieUnsigner(wordlist=args.words)
    has_unsign = unsigner.unsign(cookie)
    assert has_unsign
    secret_key = unsigner.get_secret_key()
    assert secret_key == "keyboard cat"


