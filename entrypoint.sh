#!/bin/sh
set -e

if [ "$1" = "./build/janus_core" ]; then
    echo "[Docker] Setting up Netfilter/IPTables rules..."
    
    iptables -P FORWARD DROP
    iptables -A FORWARD -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -A POSTROUTING -j MASQUERADE
    
    echo "[Docker] Firewall rules applied successfully."
fi

exec "$@"