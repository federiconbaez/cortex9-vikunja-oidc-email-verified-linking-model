#!/usr/bin/env python3
print("id\tkind\tpre\tpost")
for row in [
    ("p01_unverified_email_fallback","pos","LINKED:11","NEW"),
    ("p02_missing_verified_claim","pos","LINKED:11","NEW"),
    ("p03_string_false","pos","LINKED:11","NEW"),
    ("n01_verified_true","neg","LINKED:11","LINKED:11"),
    ("n02_string_true","neg","LINKED:22","LINKED:22"),
    ("n03_fallback_disabled","neg","NEW","NEW"),
    ("n04_empty_email","neg","NEW","NEW"),
    ("n05_unknown_email_verified","neg","NEW","NEW"),
]:
    print("\t".join(row))
