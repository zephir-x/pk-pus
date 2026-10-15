#!/bin/bash
# PUS Project 1 - Firewall Rules (iptables / ip6tables)
# Replace 8080 with the port your server is listening on

# ==========================================
# 1. BLOCKING TRAFFIC (DROP)
# ==========================================

# Blocking all incoming TCP traffic on IPv4
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP

# Blocking all incoming UDP on IPv4
sudo iptables -A INPUT -p udp --dport 8080 -j DROP

# Blocking all incoming TCP traffic on IPv6
sudo ip6tables -A INPUT -p tcp --dport 8080 -j DROP

# ==========================================
# 2. ALLOWING TRAFFIC / REMOVING BLOCKAGES (DELETE)
# ==========================================
# The -D option removes the exact same rule that we added using the -A option

sudo iptables -D INPUT -p tcp --dport 8080 -j DROP
sudo iptables -D INPUT -p udp --dport 8080 -j DROP
sudo ip6tables -D INPUT -p tcp --dport 8080 -j DROP