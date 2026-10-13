#!/bin/bash
# Regenerate the TEST-ONLY PKI in Tests/WoodpatchCoreTests/Fixtures. These certs exist
# solely for unit tests; nothing ships them and nothing trusts them outside the tests.
# Long validity (10 y) so the tests don't rot. Apple's 398-day limit applies only to certs
# that chain to system roots, and these never do.
#   trusted-ca.pem      anchor the tests pin to
#   pinned-leaf.pem     server cert for pinned.example.test, issued by trusted-ca
#   rogue-ca.pem        a different CA (stands in for a public/mis-issuing CA)
#   rogue-leaf.pem      cert for the SAME host, issued by rogue-ca (must be REJECTED)
#   client.p12          client identity (password "test") for the mTLS disposition tests
set -euo pipefail
cd "$(dirname "$0")/../Tests/WoodpatchCoreTests/Fixtures"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkca() { openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/$1.key"
  openssl req -x509 -new -key "$tmp/$1.key" -sha256 -days 3650 -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1.pem"; }
mkleaf() { openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/$1.key"
  openssl req -new -key "$tmp/$1.key" -subj "/CN=$3" -out "$tmp/$1.csr"
  openssl x509 -req -in "$tmp/$1.csr" -CA "$2.pem" -CAkey "$tmp/$2.key" -CAcreateserial -CAserial "$tmp/$2.srl" \
    -days 3650 -sha256 -extfile <(printf "%s\n" "$4") -out "$1.pem"; }
mkca trusted-ca "WoodpatchCore TEST trusted CA"
mkca rogue-ca "WoodpatchCore TEST rogue CA"
SERVER=$'subjectAltName=DNS:pinned.example.test\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature'
mkleaf pinned-leaf trusted-ca pinned.example.test "$SERVER"
mkleaf rogue-leaf rogue-ca pinned.example.test "$SERVER"
mkleaf client trusted-ca "WoodpatchCore TEST client" $'extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature'
openssl pkcs12 -export -inkey "$tmp/client.key" -in client.pem -passout pass:test -out client.p12
rm -f client.pem
echo "fixtures regenerated"
