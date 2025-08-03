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

- With a list of secret keys through the command line
```bash
$ uv run main.py --cookie s%3A897a6c4e-6156-4d06-9e7f-7309e5ba9aa0.id2ah%2B2fsa5Za2HdERwx7%2BF0C0ZaMhMzHjw2F61ebTQ -w "secret_key" -w "super_secret_key"
secret_key
```

- Or by providing a path to a wordlist
```bash
$ uv run main.py --cookie s%3A897a6c4e-6156-4d06-9e7f-7309e5ba9aa0.id2ah%2B2fsa5Za2HdERwx7%2BF0C0ZaMhMzHjw2F61ebTQ --wordlist wordlist.txt
secret_key
```
