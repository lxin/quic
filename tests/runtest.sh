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
	sleep 2
}

cleanup()
{
	exit_code=$?
	ip -6 addr del ::2/128 dev lo > /dev/null 2>&1
	ip addr del 127.0.0.2/8 dev lo > /dev/null 2>&1
	tc qdisc del dev lo root netem loss 30% > /dev/null 2>&1
	pkill func_test > /dev/null 2>&1
	pkill perf_test > /dev/null 2>&1
	pkill alpn_test > /dev/null 2>&1
	pkill ticket_test > /dev/null 2>&1
	pkill sample_test > /dev/null 2>&1
	pkill http3_test > /dev/null 2>&1
	rmmod quic_sample_test > /dev/null 2>&1
	rmmod quic > /dev/null 2>&1
	exit $exit_code
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

http3_connect()
{
	local url=$1

	echo "- $url"

	for i in `seq 3`; do
		./http3_test -c $url > /dev/null && break
		echo "WARNING: retrying $i ..."
	done
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
	tc qdisc add dev lo root netem loss 30%
	print_start "Performance Tests (IPv4, 30% packet loss on both sides)"
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	./perf_test --addr 127.0.0.1 --tot_len 1048576 --msg_len 1024 || return 1
	daemon_stop "perf_test"

	print_start "Performance Tests (IPv6, 30% packet loss on both sides)"
	daemon_run ./perf_test -l --pkey ./keys/server-key.pem --cert ./keys/server-cert.pem
	./perf_test --addr ::1 --tot_len 1048576 --msg_len 1024 || return 1
	daemon_stop "perf_test"
	tc qdisc del dev lo root netem loss 30%
}

http3_tests() {
	[ -f /usr/local/include/nghttp3/nghttp3.h -o -f /usr/include/nghttp3/nghttp3.h ] || return 0

	print_start "Http/3 Tests (http3_test -> Public Websites)"
	make http3_test > /dev/null || return 1

	http3_connect https://d.moritzbuhl.de/pub || return 1 # linuxquic
	http3_connect https://cloudflare-quic.com/ || return 1 # Cloudflare Quiche
	http3_connect https://quic.aiortc.org/ || return 1 # aioquic
	http3_connect https://facebook.com/ || return 1 # mvfst
	http3_connect https://nghttp2.org:4433/ || return 1 # ngtcp2
	http3_connect https://outlook.office.com/ || return 1 # msquic
	http3_connect https://www.litespeedtech.com/ || return 1 # lsquic
	http3_connect https://www.google.com/ || return 1 # Google quiche
	http3_connect https://quic.tech:8443/ || return 1 # Cloudflare Quiche
	http3_connect https://test.privateoctopus.com:4433 || return 1 # picoquic
	http3_connect https://www.haproxy.org/ || return 1 # haproxy
	http3_connect https://quic.nginx.org:443 || return 1 # nginx
	http3_connect https://interop.seemann.io || return 1 # quic-go
	http3_connect https://mew.org:443 || return 1 # Haskell

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

alpn_tests()
{
	print_start "ALPN and Preferred Address Tests (IPv4 -> IPv6)"
	daemon_run ./alpn_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem ::1
	./alpn_test client 127.0.0.1 1234 ::1 || return 1
	daemon_stop "alpn_test"

	print_start "ALPN and Preferred Address Tests (IPv6 -> IPv4)"
	daemon_run ./alpn_test server :: 1234 ./keys/server-key.pem ./keys/server-cert.pem 127.0.0.1
	./alpn_test client ::1 1234 127.0.0.1 || return 1
	daemon_stop "alpn_test"

	print_start "ALPN and Preferred Address Tests (IPv4 -> IPv4)"
	ip addr add 127.0.0.2/8 dev lo
	daemon_run ./alpn_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem \
		127.0.0.2
	./alpn_test client 127.0.0.1 1234 127.0.0.2 || return 1
	ip addr del 127.0.0.2/8 dev lo
	daemon_stop "alpn_test"

	print_start "ALPN and Preferred Address Tests (IPv6 -> IPv6)"
	ip -6 addr add ::2/128 dev lo
	daemon_run ./alpn_test server :: 1234 ./keys/server-key.pem ./keys/server-cert.pem ::2
	./alpn_test client ::1 1234 ::2 || return 1
	ip -6 addr del ::2/128 dev lo
	daemon_stop "alpn_test"
}

ticket_tests()
{
	print_start "Session Resumption Tests"
	daemon_run ./ticket_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
	./ticket_test client 127.0.0.1 1234 || return 1
	daemon_stop "ticket_test"
}

sample_tests()
{
	print_start "Sample Tests"
	daemon_run ./sample_test server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
	./sample_test client 127.0.0.1 1234 none none || return 1
	daemon_stop "sample_test"

}

TESTS="func perf netem http3 tlshd alpn ticket sample"
trap cleanup EXIT

[ "$1" = "" ] || TESTS=$1

start_tests || exit $?

for name in $TESTS; do
	eval ${name}_tests || exit $?
done

done_tests
