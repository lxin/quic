#!/bin/bash

print_start()
{
	echo ""
	echo "****** ["$1"] ******"
	echo ""
	sleep 1
}

daemon_stop()
{
	[ "$1" != "" ] && pkill $1 > /dev/null 2>&1
	sleep 3
}

daemon_run()
{
	$@ > /dev/null 2>&1 &
	sleep 1
}

cleanup()
{
	tc qdisc del dev lo root netem loss 15% > /dev/null 2>&1
	pkill func_test > /dev/null 2>&1
	pkill perf_test > /dev/null 2>&1
	pkill msquic_test > /dev/null 2>&1
	rmmod quic_sample_test > /dev/null 2>&1
}

make || exit 1

trap cleanup EXIT

print_start "Install Keys & Certificates"
pushd keys/ && sh ca_cert_pkey.sh || exit 1
popd

setenforce 0 > /dev/null 2>&1

print_start "Function Tests (PSK)"
daemon_run ./func_test server 0.0.0.0 1234 ./keys/server-psk.txt
./func_test client 127.0.0.1 1234 ./keys/client-psk.txt || exit 1
daemon_stop

print_start "Function Tests (Certificate)"
daemon_run ./func_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
./func_test client 127.0.0.1 1234 || exit 1
daemon_stop

print_start "Performance Tests (IPv4)"
daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
./perf_test --addr 127.0.0.1 || exit 1
daemon_stop "perf_test"

print_start "Performance Tests (IPv6)"
daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
./perf_test --addr ::1 || exit 1
daemon_stop "perf_test"

tc qdisc add dev lo root netem loss 15%
print_start "Performance Tests (IPv4, TC netem loss)"
daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
./perf_test --addr 127.0.0.1 --tot_len 1048576 --msg_len 1024 || exit 1
daemon_stop "perf_test"

print_start "Performance Tests (IPv6, TC netem loss)"
daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
./perf_test --addr ::1 --tot_len 1048576 --msg_len 1024 || exit 1
daemon_stop "perf_test"
tc qdisc del dev lo root netem loss 15%

if [ -f /usr/local/include/msquic.h -o -f /usr/include/msquic.h ]; then
	print_start "InterOperability Tests (IPv4, lkquic -> msquic)"
	make msquic_test || exit 1
	daemon_run ./msquic_test -server -cert_file:./keys/server-cert.pem -key_file:./keys/server-key.pem
	./perf_test --addr 127.0.0.1 || exit 1
	daemon_stop "msquic_test"

	print_start "InterOperability Tests (IPv4, msquic -> lkquic)"
	make msquic_test || exit 1
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	./msquic_test -client -target:127.0.0.1 || exit 1
	daemon_stop "perf_test"

	print_start "InterOperability Tests (IPv6, lkquic -> msquic)"
	make msquic_test || exit 1
	daemon_run ./msquic_test -server -cert_file:./keys/server-cert.pem -key_file:./keys/server-key.pem
	./perf_test --addr ::1 || exit 1
	daemon_stop "msquic_test"
fi

if systemctl is-active --quiet tlshd && modinfo quic_sample_test > /dev/null 2>&1; then
	print_start "Kernel Tests (kernel -> lkquic)"
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	modprobe quic_sample_test || exit 1
	rmmod quic_sample_test
	dmesg |tail -n 5
	daemon_stop "perf_test"

	print_start "Kernel Tests (lkquic -> kernel)"
	daemon_run ./perf_test --addr 127.0.0.1
	modprobe quic_sample_test role=server || exit 1
	rmmod quic_sample_test
	dmesg |tail -n 5
	daemon_stop "perf_test"
fi

print_start "Session Ticket Tests"
daemon_run ./ticket_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
./ticket_test client 127.0.0.1 1234 || exit 1
daemon_stop

print_start "Sample Tests"
daemon_run ./sample_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
./sample_test client 127.0.0.1 1234 || exit 1
daemon_stop

print_start "ALPN and Preferred Address Tests"
daemon_run ./alpn_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
./alpn_test client 127.0.0.1 1234 || exit 1
daemon_stop

echo ""
echo "ALL TESTS DONE!"
