# PUS Project 1: Network Sockets Starter Pack

This repository contains the solution for Project 1 of the Network Services Programming (PUS) course. It demonstrates low-level network communication in layers 3 and 4 of the OSI model using raw C# `System.Net.Sockets.Socket` API, completely avoiding high-level wrappers like `TcpClient` or `UdpClient`.

## Project Structure
- `src/Pus.Common/` - Shared library containing networking helpers (e.g., manual RFC 1071 Checksum calculation, IPv4/UDP manual header builder).
- `src/Pus.Server/` - Iterative server application supporting TCP, UDP, and RAW sockets.
- `src/Pus.Client/` - Client application demonstrating communication with the server.
- `scripts/` - Shell scripts and cheat sheets for firewall rules (iptables) and capability setups.

## Prerequisites
- Linux OS (or WSL2 on Windows, e.g., Ubuntu 24.04).
- .NET 8.0 SDK installed on the Linux host.
- `setcap` and `iptables` utilities available.

## How to Build (Publish)
To run the applications with Linux Capabilities (without `sudo`), they must be published as standalone executables.

```bash
# Clean solution to prevent file locks
dotnet clean

# Publish Server
dotnet publish src/Pus.Server -c Release -r linux-x64 --self-contained false -o ./publish/server

# Publish Client
dotnet publish src/Pus.Client -c Release -r linux-x64 --self-contained false -o ./publish/client
```

## Execution Guide

### Basic IPv4 TCP & UDP
Demonstrates basic iterative connection-oriented (TCP) and connectionless (UDP) communication on IPv4.

- **Server Terminal:** `./publish/server/Pus.Server --tcp` (or `--udp`)
- **Client Terminal:** `./publish/client/Pus.Client --tcp` (or `--udp`)

### IPv6 & Dual-Stack Support
Demonstrates IPv6 usage. The server uses the `DualMode` socket property to listen on `::` (`IPv6Any`), allowing it to accept both native IPv6 clients and IPv4 clients (mapped as `::ffff:x.x.x.x`).

- **Server Terminal:** `./publish/server/Pus.Server --tcp --ipv6`
- **Client Terminal (IPv6):** `./publish/client/Pus.Client --tcp --ipv6`
- **Client Terminal (IPv4 mapping test):** `./publish/client/Pus.Client --tcp`

### Raw Sockets (Layer 3)
Bypasses the OS transport layer. The client manually crafts the IPv4 and UDP headers using the `IP_HDRINCL` socket option and sends the raw bytes. The server receives the full IP datagram and manually decodes the headers to extract the payload.  
*(Requires root privileges or Capabilities)*

- **Server Terminal:** `sudo ./publish/server/Pus.Server --raw`
- **Client Terminal:** `sudo ./publish/client/Pus.Client --raw`

### Linux Capabilities (Rootless Raw Sockets)
Replaces dangerous full `sudo` execution with precise Linux Capabilities.

- `cap_net_raw` allows raw socket creation.
- `cap_net_bind_service` allows binding to privileged ports (< 1024).

```bash
# Set capabilities
sudo setcap 'cap_net_bind_service,cap_net_raw=ep' ./publish/server/Pus.Server
sudo setcap 'cap_net_raw=ep' ./publish/client/Pus.Client

# Verify
getcap ./publish/server/Pus.Server

# Run WITHOUT sudo
./publish/server/Pus.Server --tcp 80
./publish/server/Pus.Server --raw
./publish/client/Pus.Client --raw
```

### Firewall Configuration
Demonstrates network traffic control using `iptables` and `ip6tables`.

```bash
# Block all incoming IPv4 TCP traffic on port 8080
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP

# Unblock (Delete the rule)
sudo iptables -D INPUT -p tcp --dport 8080 -j DROP

# Block kernel from sending TCP RST during manual RAW Socket TCP Handshakes
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```