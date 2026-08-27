#!/bin/sh
set -e

if [ "$1" = "./build/janus" ]; then
  echo "[Docker] Setting up Netfilter/IPTables rules..."

  iptables -F
  iptables -t nat -F
  iptables -P FORWARD DROP

  iptables -I FORWARD 1 -j NFQUEUE --queue-balance 0:3

  echo "[Docker] Firewall rules applied successfully."
  iptables -vnL FORWARD --line-numbers

  # echo "==== NFQUEUE STATE (startup) ===="
  # cat /proc/net/netfilter/nfnetlink_queue || true
  # echo "================================="

  # (
  #   while true; do
  #     echo ""
  #     echo "===== LIVE IPTABLES FORWARD ====="
  #     iptables -vnL FORWARD --line-numbers || true
  #     echo "===== LIVE NFQUEUE STATE ========"
  #     cat /proc/net/netfilter/nfnetlink_queue || true
  #     echo "================================="
  #     sleep 2
  #   done
  # ) &
fi

exec "$@"