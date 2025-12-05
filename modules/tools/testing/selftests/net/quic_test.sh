#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

td_id=10

simple_if_init()
{
	local if_name=$1
	local addr4=$2
	local addr6=$3
	local vrf_name

	vrf_name=v$if_name

	ip link add $vrf_name type vrf table $((td_id++))
	ip link set dev $vrf_name up

	ip link set dev $if_name master $vrf_name
	ip link set dev $if_name up

	ip addr add $addr4 dev $if_name
	ip addr add $addr6 dev $if_name nodad
}

simple_if_fini()
{
	local if_name=$1
	local addr4=$2
	local addr6=$3
	local vrf_name

	vrf_name=v$if_name

	ip addr del $addr4 dev $if_name
	ip addr del $addr6 dev $if_name

	ip link set dev $if_name down
	ip link set dev $if_name nomaster

	ip link set dev $vrf_name down
	ip link del dev $vrf_name
}

host_create()
{
	ip link add veth0 type veth peer name veth1
	cveth=veth0
	sveth=veth1

	simple_if_init $cveth 192.0.2.1/24 2001:db8:1::1/64
	simple_if_init $sveth 192.0.2.2/24 2001:db8:1::2/64
}

host_destroy()
{
	simple_if_fini $cveth 192.0.2.1/24 2001:db8:1::1/64
	simple_if_fini $sveth 192.0.2.2/24 2001:db8:1::2/64

	ip link del $cveth
}

daemon_run()
{
	$@ > /dev/null 2>&1 &
}

server_run()
{
	$@ > /dev/null 2>&1 &
	timeout 3 bash -c 'while ! grep -q ":1234" /proc/net/quic/eps; do sleep 0.1; done'
}

client_run()
{
	$@ && timeout 3 bash -c 'while grep -q ":1234" /proc/net/quic/eps; do sleep 0.1; done'
}

cleanup()
{
	pkill -f "quic_test "
	pkill -f "quic_sample_test"
	[ -d /sys/module/quic_sample_test ] && rmmod quic_sample_test
	[ "$unload" = "1" -a -d /sys/module/quic ] && rmmod quic
	ip link set $cveth mtu 1500
	ip link set $sveth mtu 1500
	rm -rf quic_test
	host_destroy
}

trap cleanup EXIT

gcc -o quic_test quic_test.c -lpthread -Wall -Wl,--no-as-needed -O2 -g -D_GNU_SOURCE= || exit -1

[ -d /sys/module/quic ] || unload=1

do_test()
{
	local addr="192.0.2.2"
	local port=1234
	local af=$1

	[ "$af" = "6" ] && addr="2001:db8:1::2"

	echo "## IPv$af ##"

	echo "1. Functional Test:"
	client_run ./quic_test func $addr $port $cveth $sveth || exit -1
	echo ""

	echo "2. Performance Test:"
	for mtu in 1500 9000 65535; do
		ip link set $cveth mtu $mtu || exit -1
		ip link set $sveth mtu $mtu || exit -1
		for size in 256 1024 4096 16384 65536; do
			echo "=> MTU = $mtu (Message size = $size)"
			server_run ./quic_test perf server $size $addr $port $sveth
			client_run ./quic_test perf client $size $addr $port $cveth || exit -1
		done
	done
	ip link set $cveth mtu 1500
	ip link set $sveth mtu 1500
	echo ""

	echo "3. Sample Test:"
	echo "=> Userspace -> Userspace"
	server_run ./quic_test sample server $addr $port $sveth
	client_run ./quic_test sample client $addr $port $cveth || exit -1

	if modprobe -nq quic_sample_test; then
		echo "=> Userspace -> Kernel"
		daemon_run ./quic_test tlshd 2
		server_run modprobe quic_sample_test role=server ip=$addr port=$port dev=$sveth
		client_run ./quic_test sample client $addr $port $cveth || exit -1
		rmmod quic_sample_test

		echo "=> Kernel -> Userspace"
		server_run ./quic_test sample server $addr $port $sveth
		client_run modprobe quic_sample_test role=client ip=$addr port=$port dev=$cveth || \
			exit -1
		rmmod quic_sample_test
		dmesg | tail -n 5
		sleep 1
	fi
	echo ""

	echo "4. Ticket Test:"
	echo "=> Userspace -> Userspace"
	server_run ./quic_test ticket server $addr $port $sveth
	client_run ./quic_test ticket client $addr $port $cveth || exit -1

	if modprobe -nq quic_sample_test; then
		echo "=> Userspace -> Kernel"
		daemon_run ./quic_test tlshd 4
		server_run modprobe quic_sample_test alpn=ticket role=server ip=$addr port=$port \
			dev=$sveth
		client_run ./quic_test ticket client $addr $port $cveth || exit -1
		rmmod quic_sample_test

		echo "=> Kernel -> Userspace"
		server_run ./quic_test ticket server $addr $port $sveth
		client_run modprobe quic_sample_test alpn=ticket role=client ip=$addr port=$port \
			dev=$cveth || exit -1
		rmmod quic_sample_test
		dmesg | tail -n 9
		sleep 1
	fi
	echo ""
}

host_create || exit -1

do_test 4 || exit -1
do_test 6 || exit -1

! [ "$unload" = "1" -a -d /sys/module/quic ] || rmmod quic
