#!/bin/bash
# Script to generate a custom Certificate Authority (CA) and SSL certificates for Project 2

# Create a directory for certificates
mkdir -p certs
cd certs

echo "1. Generating CA Private Key and Root Certificate..."
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=PUS_Local_CA/O=PK_PUS/C=PL"

echo "2. Generating Server Private Key and Certificate Signing Request (CSR)..."
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost/O=PK_Server/C=PL"

echo "3. Signing Server Certificate with our custom CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256

echo "4. Generating Client Private Key and CSR (Needed for mTLS - Grade 4.0)..."
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=PUS_Client/O=PK_Client/C=PL"

echo "5. Signing Client Certificate with our custom CA..."
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256

echo "Certificate generation complete! Files are located in the certs/ directory."