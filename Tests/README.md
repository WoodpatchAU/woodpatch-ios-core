# Tests

**Every key and certificate under `WoodpatchCoreTests/Fixtures/` is a test-only fixture.** A secret
scanner will flag `client.p12` (password `test`) and `golden-key.x963.b64` (a P-256 private key):
neither is used by, or trusted by, any real system. They belong to a throwaway PKI made by
`scripts/make-test-fixtures.sh` (the golden CSR files are fixed `openssl req` output, see the
top-level README). This is also why apps vendor `Package.swift` + `Sources/` only.

Run the suite on the Mac build host with `scripts/mac-test.sh` (top-level README, "Testing").
