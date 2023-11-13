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
	pkill func_test > /dev/null 2>&1
	pkill perf_test > /dev/null 2>&1
	pkill msquic_test > /dev/null 2>&1
	rmmod quic_test > /dev/null 2>&1
}

make || exit 1

trap cleanup EXIT

print_start "Install Keys & Certificates"
pushd keys/ && sh ca_cert_pkey.sh || exit 1
popd

setenforce 0

print_start "Function Tests (PSK)"
daemon_run ./func_test server 0.0.0.0 1234 -psk_file:./keys/server-psk.txt
./func_test client 127.0.0.1 1234 -psk_file:./keys/client-psk.txt || exit 1
daemon_stop

print_start "Function Tests (Certificate)"
daemon_run ./func_test server 0.0.0.0 1234 -pkey_file:./keys/server-key.pem -cert_file:./keys/server-cert.pem
./func_test client 127.0.0.1 1234 || exit 1
# ./func_test client 127.0.0.1 1234 -pkey_file:./keys/client-key.pem -cert_file:./keys/client-cert.pem || exit 1
daemon_stop

print_start "Performance Tests (IPv4)"
daemon_run ./perf_test server 0.0.0.0 1234 -pkey_file:./keys/server-key.pem -cert_file:./keys/server-cert.pem
./perf_test client 127.0.0.1 1234 || exit 1
# ./perf_test client 127.0.0.1 1234 -pkey_file:./keys/client-key.pem -cert_file:./keys/client-cert.pem || exit 1
daemon_stop "perf_test"

print_start "Performance Tests (IPv6)"
daemon_run ./perf_test server :: 1234 -pkey_file:./keys/server-key.pem -cert_file:./keys/server-cert.pem
./perf_test client ::1 1234 || exit 1
# ./perf_test client ::1 1234 -pkey_file:./keys/client-key.pem -cert_file:./keys/client-cert.pem || exit 1
daemon_stop "perf_test"

if [ -f /usr/local/include/msquic.h -o -f /usr/include/msquic.h ]; then
	print_start "InterOperability Tests (IPv4, lkquic -> msquic)"
	make msquic_test || exit 1
	daemon_run ./msquic_test -server -cert_file:./keys/server-cert.pem -key_file:./keys/server-key.pem
	./perf_test client 127.0.0.1 1234 || exit 1
	daemon_stop "msquic_test"

	print_start "InterOperability Tests (IPv4, msquic -> lkquic)"
	make msquic_test || exit 1
	daemon_run ./perf_test server 0.0.0.0 1234 -pkey_file:./keys/server-key.pem -cert_file:./keys/server-cert.pem
	./msquic_test -client -target:127.0.0.1 || exit 1
	daemon_stop "perf_test"

	print_start "InterOperability Tests (IPv6, lkquic -> msquic)"
	make msquic_test || exit 1
	daemon_run ./msquic_test -server -cert_file:./keys/server-cert.pem -key_file:./keys/server-key.pem
	./perf_test client ::1 1234 || exit 1
	daemon_stop "msquic_test"
fi

if modinfo quic_test > /dev/null 2>&1; then
	print_start "Kernel Tests (kernel -> lkquic)"
	daemon_run ./perf_test server 0.0.0.0 1234 -pkey_file:./keys/server-key.pem -cert_file:./keys/server-cert.pem
	modprobe quic_test || exit 1
	rmmod quic_test
	dmesg |tail -n 5
	daemon_stop "perf_test"

	print_start "Kernel Tests (lkquic -> kernel)"
	daemon_run ./perf_test client 127.0.0.1 1234
	modprobe quic_test role=server || exit 1
	rmmod quic_test
	dmesg |tail -n 5
	daemon_stop "perf_test"
fi

print_start "Sample Tests"
daemon_run ./sample_test server 127.0.0.1 1234 ./keys/server-key.pem ./keys/server-cert.pem
./sample_test client 127.0.0.1 1234 || exit 1
daemon_stop

echo ""
echo "ALL TESTS DONE!"
