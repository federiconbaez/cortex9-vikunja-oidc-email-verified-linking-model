# cortex9-vikunja-oidc-email-verified-linking-model

Offline differential model of **CVE-2026-62367** (GHSA-xv7q-fvmc-jx96):
Vikunja's OIDC `EmailFallback` linked an SSO login to a local account by
email without checking `email_verified`. Educational, offline,
deterministic. No real IdP is contacted.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## Two semantics, always side by side

| | pre (`be36c11e`) | post (`7854f272`) |
|---|---|---|
| EmailFallback + unverified email | email-only lookup → LINKED | requires `email_verified` → NEW |
| Diff | openid.go `fallbackSearchUsers` | diff lines 39–65 (+ boolish 9–27) |

## Run

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.
