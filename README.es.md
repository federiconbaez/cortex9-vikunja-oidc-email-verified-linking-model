# cortex9-vikunja-oidc-email-verified-linking-model

Modelo diferencial offline de **CVE-2026-62367**: el `EmailFallback` OIDC
de Vikunja vinculaba cuentas locales por email sin comprobar
`email_verified`. Educativo, offline y determinista.

English: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Cómo ejecutarlo

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

Ver [LIMITATIONS.md](LIMITATIONS.md) y [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.
