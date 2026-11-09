# Limitations

- **Lookup only.** Avatar sync, user creation details, TOTP and session
  issuance are not modelled. A "NEW" outcome means "no local link", not a
  full account-provisioning simulation.
- **UsernameFallback** paths are present in the port but not exhaustively
  fixture-covered.
- **boolish** accepts bool and the strings "true"/"1"; other IdP quirks are
  not verified.
- This is not a finding. Nothing is attributed beyond SOURCES.md and the CVE.
