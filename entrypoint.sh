#!/bin/sh
set -e

if [ "$1" = "./build/janus" ]; then
  echo "[Docker] Setting up Netfilter/IPTables rules..."

  # Clean slate each boot
  iptables -F
  iptables -t nat -F

  # Strict: nothing forwards unless Janus verdicts it
  iptables -P FORWARD DROP

  # IMPORTANT: no --queue-bypass for strict DPI
  iptables -I FORWARD 1 -j NFQUEUE --queue-balance 0:3

  echo "[Docker] Firewall rules applied successfully."
  iptables -vnL FORWARD --line-numbers

  echo "==== NFQUEUE STATE (startup) ===="
  cat /proc/net/netfilter/nfnetlink_queue || true
  echo "================================="

  # ---- LIVE DEBUG (non-blocking) ----
  (
    while true; do
      echo ""
      echo "===== LIVE IPTABLES FORWARD ====="
      iptables -vnL FORWARD --line-numbers || true
      echo "===== LIVE NFQUEUE STATE ========"
      cat /proc/net/netfilter/nfnetlink_queue || true
      echo "================================="
      sleep 2
    done
  ) &
fi

exec "$@"