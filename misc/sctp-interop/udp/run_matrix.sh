#!/usr/bin/env bash
# SCTP-over-UDP (RFC 6951) interop matrix: Go <-> Go, rust-sctp, usrsctp.
# Each peer runs the same echo protocol: 100 messages, stream i%5,
# PPID 0x10000+i, message 50 is 200 KiB (64 KiB against rust-sctp, whose
# engine caps messages at 64 KiB), then a graceful SHUTDOWN.
#
# Environment:
#   RUSTC    rust-sctp stage1 rustc (skip Rust when unset)
#   USRSCTP  usrsctp checkout with a cmake build in $USRSCTP/build (skip when unset)
set -u
cd "$(dirname "$0")"
GOROOT=$(cd ../../.. && pwd)
export GOROOT
mkdir -p logs
# Build every peer afresh: a failed build must stop the run, never fall back
# to a stale binary from an earlier run.
rm -rf bin/matrix
mkdir -p bin/matrix
die() { echo "FAIL build: $*" >&2; exit 1; }
"$GOROOT/bin/go" build -o bin/matrix/goecho ./goecho/main.go || die goecho
"$GOROOT/bin/go" build -o bin/matrix/udprelay ./udprelay/main.go || die udprelay
have_rust=false have_usrsctp=false
if [ -n "${RUSTC:-}" ]; then
	"$RUSTC" -O --edition 2021 -o bin/matrix/rustecho rustecho/main.rs || die rustecho
	BIG=1 "$RUSTC" -O --edition 2021 -o bin/matrix/rustecho64k rustecho/main.rs || die rustecho64k
	have_rust=true
fi
if [ -n "${USRSCTP:-}" ]; then
	cc -O2 -include pthread.h -include errno.h -I"$USRSCTP/usrsctplib" usrsctpecho/usrsctpecho.c \
		"$USRSCTP/build/usrsctplib/libusrsctp.a" -lpthread -o bin/matrix/usrsctpecho || die usrsctpecho
	have_usrsctp=true
fi
B=bin/matrix

rc=0
pair() { # name server-cmd client-cmd
	local name=$1 s=$2 c=$3
	$s > logs/$name-server.log 2>&1 & local sp=$!
	sleep 0.5
	timeout 70 $c > logs/$name-client.log 2>&1; local cc=$?
	for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 $sp 2>/dev/null || break; sleep 0.5; done
	kill $sp 2>/dev/null; wait $sp; local sc=$?
	if [ $cc = 0 ] && [ $sc = 0 ]; then echo "PASS $name"; else echo "FAIL $name (client=$cc server=$sc, logs/$name-*.log)"; rc=1; fi
}
p=21000
pair a-go-go "$B/goecho -mode server -addr 127.0.0.1:$p" "$B/goecho -mode client -addr 127.0.0.1:$p"
p=$((p + 1))
pair a-go-go-encap "$B/goecho -mode server -addr 127.0.0.1:$p -lencap 31001" \
	"$B/goecho -mode client -addr 127.0.0.1:$p -local 127.0.0.1:21100 -lencap 31100 -rencap 31001"
if $have_rust; then
	p=$((p + 1))
	pair b-goserver-rustclient "$B/goecho -mode server -addr 127.0.0.1:$p -big 65536" "$B/rustecho64k client 127.0.0.1:$p"
	p=$((p + 1))
	pair b-rustserver-goclient "$B/rustecho64k server 127.0.0.1:$p" "$B/goecho -mode client -addr 127.0.0.1:$p -big 65536"
fi
if $have_usrsctp; then
	p=$((p + 1))
	pair c-usrsctpserver-goclient "$B/usrsctpecho server $p 3$p" "$B/goecho -mode client -addr 127.0.0.1:$p -rencap 3$p"
	p=$((p + 1))
	pair c-goserver-usrsctpclient "$B/goecho -mode server -addr 127.0.0.1:$p" "$B/usrsctpecho client 127.0.0.1 $p 3$p $p"
fi
GOECHO=$B/goecho ./d-kernel.sh >/dev/null 2>&1; case $? in 0) echo "PASS d-kernel";; 2) echo "SKIP d-kernel (sysctls unset)";; *) echo "FAIL d-kernel"; rc=1;; esac
exit $rc
