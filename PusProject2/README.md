# PUS Project 2: Secure Communication (TLS & QUIC)

This repository contains the solution for Project 2 of the Network Services Programming (PUS) course. It demonstrates secure network communication using Transport Layer Security (TLS 1.3) over TCP, Custom Certificate Authority (CA) validation, Mutual TLS (mTLS), and the modern QUIC protocol over UDP using the native .NET `System.Net.Quic` API.

## Project Structure
- `src/Pus.Server/` - Server application supporting TLS (TCP) and QUIC (UDP) protocols, enforcing mTLS and ALPN negotiation.
- `src/Pus.Client/` - Client application supporting TLS and QUIC, utilizing custom CA root trust validation.
- `scripts/` - Bash scripts to automate the generation of a Custom Certificate Authority (CA) and X.509 PEM certificates via OpenSSL.

## Prerequisites
- Linux OS (or WSL2 on Windows, e.g., Ubuntu 24.04).
- .NET 8.0 SDK installed on the Linux host.
- `openssl` utility for certificate generation.
- **MsQuic Library:** Required for `System.Net.Quic` on Linux.

### Installing MsQuic on Ubuntu 24.04
Since `libmsquic` is not in the default Ubuntu 24.04 repositories, you must add the Microsoft package repository first:
```bash
wget https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update && sudo apt install libmsquic -y
```

## Initial Setup: Certificates Generation
Before running the applications, you must generate the cryptographic material. The provided script uses OpenSSL to create a local Certificate Authority (CA), and signs both Server and Client certificates in PEM format.

```bash
# Navigate to the project root and execute the script
chmod +x scripts/generate_certs.sh
./scripts/generate_certs.sh
```

This will create a `certs/` directory containing `ca.crt`, `server.crt`, `server.key`, `client.crt`, and `client.key`.

## Execution Guide (Grade Requirements)

### Grades 3.0 - 4.0: TLS over TCP & Mutual TLS (mTLS)
Demonstrates secure connection-oriented communication over TCP using `SslStream`.

- **Grade 3.0:** Wraps raw sockets in TLS encryption.
- **Grade 3.5:** The client strictly validates the server's certificate against the locally generated CA (`ca.crt`) using `X509ChainTrustMode.CustomRootTrust`, completely bypassing the OS-level global trust store.
- **Grade 4.0 (mTLS):** The server enforces client authentication (`clientCertificateRequired: true`). Both parties exchange and cryptographically verify each other's certificates.

#### Execution:
Open two terminals and run:

- **Server Terminal:** `dotnet run --project src/Pus.Server --tls`
- **Client Terminal:** `dotnet run --project src/Pus.Client --tls`

### Grades 4.5 - 5.0: QUIC Protocol over UDP
Demonstrates the modern, multiplexed, 1-RTT secure transport protocol over UDP using `System.Net.Quic`.

- **Grade 4.5:** QUIC Client implementation connecting over UDP, enforcing TLS 1.3 CA validation, and opening bidirectional streams.
- **Grade 5.0:** QUIC Server implementation handling UDP datagrams, negotiating Application-Layer Protocol (ALPN: `pus-quic`), and echoing decrypted stream data.

#### Execution:
Open two terminals and run:

- **Server Terminal:** `dotnet run --project src/Pus.Server --quic`
- **Client Terminal:** `dotnet run --project src/Pus.Client --quic`