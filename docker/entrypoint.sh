#!/bin/sh
set -e

WG_IFACE="wg0"
WG_ADDR="${WG_ADDR:-10.13.37.1/24}"
WG_PORT="${WG_PORT:-51820}"
BURP_PORT="${BURP_PORT:-8080}"

# Create WireGuard interface using the kernel module (built into Docker Desktop's kernel)
ip link add "$WG_IFACE" type wireguard
wg setconf "$WG_IFACE" /etc/wireguard/wg0.conf
ip addr add "$WG_ADDR" dev "$WG_IFACE"
ip link set up dev "$WG_IFACE"

# ip_forward is set via Docker --sysctl at container start; verify it
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
    echo "WARNING: ip_forward not enabled — attempting sysctl fallback"
    sysctl -w net.ipv4.ip_forward=1 || echo "WARNING: could not enable ip_forward; traffic forwarding may not work"
fi

# Resolve Docker host IPv4 — works on Docker Desktop (macOS + Windows)
HOST_IP=$(getent ahostsv4 host.docker.internal 2>/dev/null | awk '{print $1; exit}')
if [ -z "$HOST_IP" ]; then
    # Fallback: default route gateway (Linux native Docker)
    HOST_IP=$(ip route | awk '/default/ {print $3; exit}')
fi

echo "Redirecting HTTP/HTTPS via proxy bridge to Burp at $HOST_IP:$BURP_PORT"

# REDIRECT phone HTTP/HTTPS to local proxy listeners.
iptables -t nat -A PREROUTING -i "$WG_IFACE" -p tcp --dport 80  -j REDIRECT --to-port 8079
iptables -t nat -A PREROUTING -i "$WG_IFACE" -p tcp --dport 443 -j REDIRECT --to-port 8443

# Python proxy: reads SNI/Host, routes to Burp or directly for excepted hosts
BURP_HOST="$HOST_IP" BURP_PORT="$BURP_PORT" \
  HTTP_LISTEN=8079 HTTPS_LISTEN=8443 \
  EXCEPTION_HOSTS="$EXCEPTION_HOSTS" \
  CTRL_PORT="${CTRL_PORT:-9292}" \
  python3 /proxy.py &

# Block QUIC (HTTP/3 over UDP 443) — forces apps to fall back to TCP 443
iptables -A FORWARD -i "$WG_IFACE" -p udp --dport 443 -j REJECT
iptables -A FORWARD -i "$WG_IFACE" -j ACCEPT
iptables -A FORWARD -o "$WG_IFACE" -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Drop IPv6 forwarding — forces apps to fall back to IPv4 (client config tunnels ::/0)
ip6tables -A FORWARD -j DROP 2>/dev/null || echo "ip6tables not available, skipping IPv6 block"

echo "WireGuard VPN is up on $WG_IFACE (port $WG_PORT)"
wg show "$WG_IFACE"

# Keep alive — wg show every 30s so logs are useful
while true; do
    sleep 30
    wg show "$WG_IFACE" handshake 2>/dev/null || true
done
