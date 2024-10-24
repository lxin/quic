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
	tc qdisc del dev lo root netem loss 10% > /dev/null 2>&1
	pkill func_test > /dev/null 2>&1
	pkill perf_test > /dev/null 2>&1
	pkill msquic_test > /dev/null 2>&1
	pkill alpn_test > /dev/null 2>&1
	pkill ticket_test > /dev/null 2>&1
	pkill sample_test > /dev/null 2>&1
	pkill http3_test > /dev/null 2>&1
	rmmod quic_sample_test > /dev/null 2>&1
	rmmod quic > /dev/null 2>&1
}

start_tests()
{
	make || return 1
	setenforce 0 > /dev/null 2>&1
	modprobe -a udp_tunnel ip6_udp_tunnel || return 1
	if [ -f ../modules/net/quic/quic.ko ]; then
		[ -d /sys/module/quic ] || insmod ../modules/net/quic/quic.ko || return 1
	else
		modprobe quic || return 1
	fi

	print_start "Install Keys & Certificates"
	pushd keys/
	sh ca_cert_pkey_psk.sh || return 1
	if systemctl is-active --quiet tlshd; then
		sh ca_cert_pkey_psk.sh psk-keyring || return 1
		systemctl restart tlshd || return 1
	fi
	popd
	if [ -d /etc/pki/ca-trust/source/anchors/ ]; then
		install keys/ca-cert.pem /etc/pki/ca-trust/source/anchors/ca-cert.pem
		update-ca-trust
	elif [ -d /usr/local/share/ca-certificates/ ]; then
		install keys/ca-cert.pem /usr/local/share/ca-certificates/ca-cert.crt
		update-ca-certificates
	fi
}

done_tests()
{
	echo ""
	echo "ALL TESTS DONE!"
}

func_tests()
{
	print_start "Function Tests (PSK)"
	daemon_run ./func_test server 0.0.0.0 1234 ./keys/server-psk.txt
	./func_test client 127.0.0.1 1234 ./keys/client-psk.txt || return 1
	daemon_stop "func_test"

	print_start "Function Tests (Certificate)"
	daemon_run ./func_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
	./func_test client 127.0.0.1 1234 || return 1
	daemon_stop "func_test"
}

perf_tests()
{
	print_start "Performance Tests (IPv4)"
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	./perf_test --addr 127.0.0.1 || return 1
	daemon_stop "perf_test"

	print_start "Performance Tests (IPv6, Disable 1RTT Encryption)"
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem \
				  --cert ./keys/server-cert.pem --no_crypt
	./perf_test --addr ::1 --no_crypt || return 1
	daemon_stop "perf_test"

	print_start "Performance Tests (IPv6)"
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	./perf_test --addr ::1 || return 1
	daemon_stop "perf_test"
}

netem_tests()
{
	modprobe -q sch_netem || return 0
	tc qdisc add dev lo root netem loss 10%
	print_start "Performance Tests (IPv4, 10% packet loss on both sides)"
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	./perf_test --addr 127.0.0.1 --tot_len 1048576 --msg_len 1024 || return 1
	daemon_stop "perf_test"

	print_start "Performance Tests (IPv6, 10% packet loss on both sides)"
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	./perf_test --addr ::1 --tot_len 1048576 --msg_len 1024 || return 1
	daemon_stop "perf_test"
	tc qdisc del dev lo root netem loss 10%
}

msquic_tests() {
	[ -f /usr/local/include/msquic.h -o -f /usr/include/msquic.h ] || return 0

	print_start "InterOperability Tests (IPv4, lkquic -> msquic)"
	make msquic_test || return 1
	daemon_run ./msquic_test -server -cert_file:./keys/server-cert.pem \
					 -key_file:./keys/server-key.pem
	./perf_test --addr 127.0.0.1 || return 1
	daemon_stop "msquic_test"

	print_start "InterOperability Tests (IPv4, msquic -> lkquic)"
	make msquic_test || return 1
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	./msquic_test -client -target:127.0.0.1 || return 1
	daemon_stop "perf_test"

	print_start "InterOperability Tests (IPv6, lkquic -> msquic)"
	make msquic_test || return 1
	daemon_run ./msquic_test -server -cert_file:./keys/server-cert.pem \
					 -key_file:./keys/server-key.pem
	./perf_test --addr ::1 || return 1
	daemon_stop "msquic_test"
}

http3_tests() {
	[ -f /usr/local/include/nghttp3/nghttp3.h -o -f /usr/include/nghttp3/nghttp3.h ] || return 0

	print_start "Http/3 Tests (http3_test -> Public Websites)"
	make http3_test > /dev/null || return 1
	echo "- https://cloudflare-quic.com/"
	./http3_test -c https://cloudflare-quic.com/ > /dev/null || return 1  # Cloudflare Quiche
	echo "- https://quic.aiortc.org/"
	./http3_test -c https://quic.aiortc.org/ > /dev/null || return 1  # aioquic
	echo "- https://facebook.com/"
	./http3_test -c https://facebook.com/ > /dev/null || return 1 # mvfst
	echo "- https://nghttp2.org:4433/"
	./http3_test -c https://nghttp2.org:4433/ > /dev/null || return 1 # ngtcp2
	echo "- https://outlook.office.com/"
	./http3_test -c https://outlook.office.com/ > /dev/null || return 1 # msquic
	echo "- https://www.litespeedtech.com/"
	./http3_test -c https://www.litespeedtech.com/ > /dev/null || return 1  # lsquic
	echo "- https://www.google.com/"
	./http3_test -c https://www.google.com/ > /dev/null || return 1 # Google quiche
	echo "- https://quic.tech:8443/"
	./http3_test -c https://quic.tech:8443/ > /dev/null || return 1 # Cloudflare Quiche
	echo "- https://test.privateoctopus.com:4433"
	./http3_test -c https://test.privateoctopus.com:4433/ > /dev/null || return 1 # picoquic

	print_start "Http/3 Tests (http3_test client -> http3_test server)"
	daemon_run ./http3_test -s 127.0.0.1:443 ./keys/server-key.pem ./keys/server-cert.pem
	./http3_test -c https://localhost/ || return 1
	daemon_stop "http3_test"
}

tlshd_tests()
{
	systemctl is-active --quiet tlshd || return 0

	print_start "Kernel Tests (kernel -> lkquic, Certificate, Sample)"
	if [ -f ../modules/net/quic/quic_sample_test.ko ]; then
		daemon_run ./sample_test server 0.0.0.0 1234 ./keys/server-key.pem \
							     ./keys/server-cert.pem sample
		insmod ../modules/net/quic/quic_sample_test.ko || return 1
	else
		modprobe -n quic_sample_test || return 0
		daemon_run ./sample_test server 0.0.0.0 1234 ./keys/server-key.pem \
							     ./keys/server-cert.pem sample
		modprobe quic_sample_test || return 1
	fi
	rmmod quic_sample_test
	dmesg | tail -n 5
	daemon_stop "sample_test"

	print_start "Kernel Tests (lkquic -> kernel, Certificate, Sample)"
	if [ -f ../modules/net/quic/quic_sample_test.ko ]; then
		daemon_run ./sample_test client 127.0.0.1 1234 none none sample
		insmod ../modules/net/quic/quic_sample_test.ko role=server || return 1
	else
		modprobe -n quic_sample_test || return 0
		daemon_run ./sample_test client 127.0.0.1 1234 none none sample
		modprobe quic_sample_test role=server || return 1
	fi
	rmmod quic_sample_test
	dmesg | tail -n 5
	daemon_stop "sample_test"

	print_start "Kernel Tests (kernel -> lkquic, PSK, Sample)"
	PSK=`keyctl show @u |grep test1 |awk '{print $1}'`
	if [ -f ../modules/net/quic/quic_sample_test.ko ]; then
		daemon_run ./sample_test server 0.0.0.0 1234 ./keys/server-psk.txt none sample
		insmod ../modules/net/quic/quic_sample_test.ko psk=$PSK || return 1
	else
		modprobe -n quic_sample_test || return 0
		daemon_run ./sample_test server 0.0.0.0 1234 ./keys/server-psk.txt none sample
		modprobe quic_sample_test psk=$PSK || return 1
	fi
	rmmod quic_sample_test
	dmesg | tail -n 5
	daemon_stop "sample_test"

	print_start "Kernel Tests (lkquic -> kernel, PSK, Sample)"
	if [ -f ../modules/net/quic/quic_sample_test.ko ]; then
		daemon_run ./sample_test client 127.0.0.1 1234 ./keys/client-psk.txt none sample
		insmod ../modules/net/quic/quic_sample_test.ko role=server psk=1 || return 1
	else
		modprobe -n quic_sample_test || return 0
		daemon_run ./sample_test client 127.0.0.1 1234 ./keys/client-psk.txt none sample
		modprobe quic_sample_test role=server psk=1 || return 1
	fi
	rmmod quic_sample_test
	dmesg | tail -n 5
	daemon_stop "sample_test"

	print_start "Kernel Tests (kernel -> lkquic, Certificate, Session Resumption)"
	if [ -f ../modules/net/quic/quic_sample_test.ko ]; then
		daemon_run ./ticket_test server 0.0.0.0 1234 ./keys/server-key.pem \
							     ./keys/server-cert.pem ticket
		insmod ../modules/net/quic/quic_sample_test.ko alpn=ticket || return 1
	else
		modprobe -n quic_sample_test || return 0
		daemon_run ./ticket_test server 0.0.0.0 1234 ./keys/server-key.pem \
							     ./keys/server-cert.pem ticket
		modprobe quic_sample_test alpn=ticket || return 1
	fi
	rmmod quic_sample_test
	dmesg | tail -n 5
	daemon_stop "ticket_test"

	print_start "Kernel Tests (lkquic -> kernel, Certificate, Session Resumption)"
	if [ -f ../modules/net/quic/quic_sample_test.ko ]; then
		daemon_run ./ticket_test client 127.0.0.1 1234 ticket
		insmod ../modules/net/quic/quic_sample_test.ko role=server alpn=ticket || return 1
	else
		modprobe -n quic_sample_test || return 0
		daemon_run ./ticket_test client 127.0.0.1 1234 ticket
		modprobe quic_sample_test role=server alpn=ticket || return 1
	fi
	rmmod quic_sample_test
	dmesg | tail -n 5
	daemon_stop "ticket_test"
}

sample_tests()
{
	print_start "Session Resumption Tests"
	daemon_run ./ticket_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
	./ticket_test client 127.0.0.1 1234 || return 1
	daemon_stop "ticket_test"

	print_start "Sample Tests"
	daemon_run ./sample_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
	./sample_test client 127.0.0.1 1234 none none || return 1
	daemon_stop "sample_test"

	print_start "ALPN and Preferred Address Tests"
	daemon_run ./alpn_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
	./alpn_test client 127.0.0.1 1234 || return 1
	daemon_stop "alpn_test"
}

TESTS="func perf netem msquic http3 tlshd sample"
trap cleanup EXIT

[ "$1" = "" ] || TESTS=$1

start_tests || exit $?

for name in $TESTS; do
	eval ${name}_tests || exit $?
done

done_tests
