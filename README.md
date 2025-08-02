# cookie-monster

## Why

A common step in a recon workflow is usually to check for session hijacking.

If a session cookie has been signed using a weak (or leaked) secret key, you can hijack the targetted session.

cookie-monster is willing to automate the recovery of the said secret key.

## What

cookie-monster is currently handling the below framework cookie session:

- express-session

More eventually coming.

## How

You need the python package manager [uv](https://docs.astral.sh/uv/getting-started/installation/)

Once cloned, you can install the project:

```bash
$ uv sync
```

And use cookie-monster:

With a list of secret keys through the command line:
```bash
$ uv run main.py --cookie 089ef98d-191a-43d0-a262-e0c78b34ce5c.WlvcIjHCE2XhlfFDeveCG4fo9jPFqbNFEkejBlYiKGo -w "secret_key" -w "super_secret_key"
secret_key
```

Or by providing a path to a wordlist:
```bash
$ uv run main.py --cookie 089ef98d-191a-43d0-a262-e0c78b34ce5c.WlvcIjHCE2XhlfFDeveCG4fo9jPFqbNFEkejBlYiKGo --wordlist wordlist.txt
secret_key
```
