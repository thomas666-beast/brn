#!/usr/bin/env bash
set -euo pipefail
umask 077

force=false
if [[ "${1:-}" == "--force" && $# -eq 1 ]]; then
  force=true
elif [[ $# -ne 0 ]]; then
  echo "Usage: bash scripts/generate-test-certs.sh [--force]" >&2
  exit 2
fi
command -v openssl >/dev/null || { echo "OpenSSL is required" >&2; exit 1; }
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/certs"
mkdir -p -- "$out"
for name in ca.cert.der server.cert.der server.key.der; do
  if [[ ( -e "$out/$name" || -L "$out/$name" ) && "$force" != true ]]; then
    echo "Refusing to replace $out/$name. Use --force only for disposable test fixtures." >&2
    exit 1
  fi
done
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$work/ca.key.pem"
openssl req -new -x509 -sha256 -days 30 \
  -key "$work/ca.key.pem" -out "$work/ca.cert.pem" \
  -subj "/CN=BRN Disposable Test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$work/server.key.pem"
openssl req -new -sha256 -key "$work/server.key.pem" \
  -subj "/CN=localhost" -out "$work/server.csr.pem"
cat > "$work/server.ext" <<'EXTENSIONS'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXTENSIONS
serial="$(openssl rand -hex 16)"
openssl x509 -req -sha256 -days 7 \
  -in "$work/server.csr.pem" \
  -CA "$work/ca.cert.pem" -CAkey "$work/ca.key.pem" \
  -set_serial "0x$serial" -extfile "$work/server.ext" \
  -out "$work/server.cert.pem"
openssl verify -CAfile "$work/ca.cert.pem" -purpose sslserver \
  -verify_hostname localhost "$work/server.cert.pem"
openssl x509 -in "$work/ca.cert.pem" -outform DER -out "$work/ca.cert.der"
openssl x509 -in "$work/server.cert.pem" -outform DER -out "$work/server.cert.der"
openssl pkcs8 -topk8 -nocrypt -in "$work/server.key.pem" \
  -outform DER -out "$work/server.key.der"
for name in ca.cert.der server.cert.der server.key.der; do
  install -m 600 "$work/$name" "$out/$name"
done
echo "Generated disposable test fixtures in certs/. Never use these as deployment credentials."
