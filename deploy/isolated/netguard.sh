#!/bin/sh
# Egress allowlist for the agent's network namespace.
#
# The agent container joins this namespace (network_mode: service:netguard)
# with every capability dropped, so it cannot alter these rules. The only
# outbound connection permitted is TCP to the harness API.
set -eu

HARNESS_HOST="${HARNESS_HOST:-harness}"
HARNESS_PORT="${HARNESS_PORT:-8700}"

i=0
until HARNESS_IP="$(getent hosts "$HARNESS_HOST" | awk '{print $1; exit}')" && [ -n "$HARNESS_IP" ]; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "netguard: cannot resolve $HARNESS_HOST" >&2; exit 1; }
  sleep 0.5
done

iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT                                   # loopback (includes Docker's embedded DNS at 127.0.0.11)
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -d "$HARNESS_IP" --dport "$HARNESS_PORT" -j ACCEPT
iptables -A OUTPUT -p tcp -j REJECT --reject-with tcp-reset          # fail fast and visibly
iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
iptables -P OUTPUT DROP

ip6tables -F OUTPUT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -j REJECT
ip6tables -P OUTPUT DROP

echo "netguard: agent egress limited to tcp://$HARNESS_IP:$HARNESS_PORT"
iptables -S OUTPUT
touch /tmp/netguard-ready
exec sleep infinity
