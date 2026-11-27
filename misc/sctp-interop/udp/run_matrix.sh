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
mkdir -p bin logs
"$GOROOT/bin/go" build -o bin/goecho ./goecho/main.go
"$GOROOT/bin/go" build -o bin/udprelay ./udprelay
if [ -n "${RUSTC:-}" ]; then
	"$RUSTC" -O --edition 2021 -o bin/rustecho rustecho/main.rs
	BIG=1 "$RUSTC" -O --edition 2021 -o bin/rustecho64k rustecho/main.rs
fi
if [ -n "${USRSCTP:-}" ]; then
	cc -O2 -include pthread.h -include errno.h -I"$USRSCTP/usrsctplib" usrsctpecho/usrsctpecho.c \
		"$USRSCTP/build/usrsctplib/libusrsctp.a" -lpthread -o bin/usrsctpecho
fi

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
pair a-go-go "bin/goecho -mode server -addr 127.0.0.1:$p" "bin/goecho -mode client -addr 127.0.0.1:$p"
p=$((p + 1))
pair a-go-go-encap "bin/goecho -mode server -addr 127.0.0.1:$p -lencap 31001" \
	"bin/goecho -mode client -addr 127.0.0.1:$p -local 127.0.0.1:21100 -lencap 31100 -rencap 31001"
if [ -x bin/rustecho64k ] && [ -n "${RUSTC:-}" ]; then
	p=$((p + 1))
	pair b-goserver-rustclient "bin/goecho -mode server -addr 127.0.0.1:$p -big 65536" "bin/rustecho64k client 127.0.0.1:$p"
	p=$((p + 1))
	pair b-rustserver-goclient "bin/rustecho64k server 127.0.0.1:$p" "bin/goecho -mode client -addr 127.0.0.1:$p -big 65536"
fi
if [ -n "${USRSCTP:-}" ]; then
	p=$((p + 1))
	pair c-usrsctpserver-goclient "bin/usrsctpecho server $p 3$p" "bin/goecho -mode client -addr 127.0.0.1:$p -rencap 3$p"
	p=$((p + 1))
	pair c-goserver-usrsctpclient "bin/goecho -mode server -addr 127.0.0.1:$p" "bin/usrsctpecho client 127.0.0.1 $p 3$p $p"
fi
./d-kernel.sh >/dev/null 2>&1; case $? in 0) echo "PASS d-kernel";; 2) echo "SKIP d-kernel (sysctls unset)";; *) echo "FAIL d-kernel"; rc=1;; esac
exit $rc
