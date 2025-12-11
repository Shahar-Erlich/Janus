#!/bin/sh

iptables -A FORWARD -i eth0 -o eth1 -j NFQUEUE --queue-num 0   # Untrusted → Trusted
iptables -A FORWARD -i eth1 -o eth0 -j NFQUEUE --queue-num 0   # Trusted → Untrusted

iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate NEW,ESTABLISHED -j NFQUEUE --queue-num 0

# Start the core application
sleep 1
exec ./core

