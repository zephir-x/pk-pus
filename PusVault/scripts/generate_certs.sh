#!/bin/bash
# Generates Custom Root CA and Server X.509 certificates for PUS-Vault (PVSP v1.0).
# Includes X.509 v3 Subject Alternative Name (SAN) and Extended Key Usage (serverAuth)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_ROOT/certs"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "[1/3] Generating Custom Root CA private key and self-signed certificate (ca.crt)..."
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/C=PL/O=PK_PUS/CN=PUS_Vault_Root_CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "[2/3] Generating Server private key and CSR (server.key, server.csr)..."
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/C=PL/O=PK_PUS_Vault/CN=localhost"

echo "[3/3] Signing Server certificate with Custom Root CA (including SAN and EKU serverAuth)..."
cat > server_ext.cnf <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:pus-vault-server, IP:127.0.0.1, IP:::1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 -extfile server_ext.cnf

# Enforce strict owner-only permissions (0600) on private keys as required by MVP spec
chmod 600 ca.key server.key
chmod 644 ca.crt server.crt
rm -f server.csr server_ext.cnf

echo "Success! Certificates generated in: $CERTS_DIR"
ls -l "$CERTS_DIR"