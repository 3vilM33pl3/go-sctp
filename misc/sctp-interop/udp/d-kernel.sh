#!/usr/bin/env bash
# Test (d): Go SCTP-over-UDP against Linux kernel UDP encapsulation (5.11+).
#
# Needs, as root (it changes SCTP for the whole host until reverted):
#   sudo sysctl -w net.sctp.udp_port=9899 net.sctp.encap_port=9900
# Revert with:
#   sudo sysctl -w net.sctp.udp_port=0 net.sctp.encap_port=0
#
# udp_port: the kernel listens on UDP 9899 and decapsulates SCTP.
# encap_port: the kernel encapsulates outgoing SCTP to UDP 9900 by default
# (replies on an association follow the peer's observed UDP source port).
set -u
cd "$(dirname "$0")"
G=${GOECHO:-bin/goecho}
[ -x "$G" ] || { echo "FAIL: no goecho at $G" >&2; exit 1; }
mkdir -p logs
up=$(sysctl -n net.sctp.udp_port) ep=$(sysctl -n net.sctp.encap_port)
if [ "$up" = 0 ] || [ "$ep" = 0 ]; then
	echo "SKIP: net.sctp.udp_port=$up net.sctp.encap_port=$ep; run:"
	echo "  sudo sysctl -w net.sctp.udp_port=9899 net.sctp.encap_port=9900"
	exit 2
fi
rc=0
pair() { # name server-cmd client-cmd
	local name=$1 s=$2 c=$3
	$s > logs/$name-server.log 2>&1 & local sp=$!
	sleep 0.5
	timeout 70 $c > logs/$name-client.log 2>&1; local cc=$?
	for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 $sp 2>/dev/null || break; sleep 0.5; done
	kill $sp 2>/dev/null; wait $sp; local sc=$?
	echo "=== $name client=$cc server=$sc"; cat logs/$name-client.log logs/$name-server.log
	[ $cc = 0 ] && [ $sc = 0 ] || rc=1
}
# Kernel SCTP server <- Go UDP-only client (sends to the kernel's UDP port).
pair d1-kernelserver-goudpclient \
	"$G -mode server -transport native -addr 127.0.0.1:19990" \
	"$G -mode client -addr 127.0.0.1:19990 -rencap $up"
# Go UDP-only server on UDP $ep <- kernel SCTP client (encapsulates to $ep).
pair d2-goudpserver-kernelclient \
	"$G -mode server -addr 127.0.0.1:19991 -lencap $ep" \
	"$G -mode client -transport native -addr 127.0.0.1:19991"
exit $rc
