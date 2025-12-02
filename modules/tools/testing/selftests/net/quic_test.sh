#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

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
	[ -n "$saved_mtu" ] && ip link set lo mtu $saved_mtu
	rm -rf quic_test
}

trap cleanup EXIT

gcc -o quic_test quic_test.c -lpthread -Wall -Wl,--no-as-needed -O2 -g -D_GNU_SOURCE= || exit -1

[ -d /sys/module/quic ] || unload=1

do_test()
{
	local addr="127.0.0.1"
	local af=$1

	[ "$af" = "6" ] && addr="::1"

	echo "## IPv$af ##"

	echo "1. Functional Test:"
	client_run ./quic_test func $af || exit -1
	echo ""

	echo "2. Performance Test:"
	saved_mtu=`cat /sys/class/net/lo/mtu`
	for mtu in 1500 9000 65536; do
		ip link set lo mtu $mtu
		for size in 256 1024 4096 16384 65536; do
			echo "=> MTU = $mtu (Message size = $size)"
			server_run ./quic_test perf $af server $size
			client_run ./quic_test perf $af client $size || exit -1
		done
	done
	ip link set lo mtu $saved_mtu
	echo ""

	echo "3. Sample Test:"
	echo "=> Userspace -> Userspace"
	server_run ./quic_test sample $af server
	client_run ./quic_test sample $af client || exit -1

	if modprobe -nq quic_sample_test; then
		echo "=> Userspace -> Kernel"
		daemon_run ./quic_test tlshd 2
		server_run modprobe quic_sample_test role=server ip=$addr
		client_run ./quic_test sample $af client || exit -1
		rmmod quic_sample_test

		echo "=> Kernel -> Userspace"
		server_run ./quic_test sample $af server
		client_run modprobe quic_sample_test role=client ip=$addr || exit -1
		rmmod quic_sample_test
		dmesg | tail -n 5
		sleep 1
	fi
	echo ""

	echo "4. Ticket Test:"
	echo "=> Userspace -> Userspace"
	server_run ./quic_test ticket $af server
	client_run ./quic_test ticket $af client || exit -1

	if modprobe -nq quic_sample_test; then
		echo "=> Userspace -> Kernel"
		daemon_run ./quic_test tlshd 4
		server_run modprobe quic_sample_test role=server alpn=ticket ip=$addr
		client_run ./quic_test ticket $af client || exit -1
		rmmod quic_sample_test

		echo "=> Kernel -> Userspace"
		server_run ./quic_test ticket $af server
		client_run modprobe quic_sample_test role=client alpn=ticket ip=$addr || exit -1
		rmmod quic_sample_test
		dmesg | tail -n 9
		sleep 1
	fi
	echo ""
}

do_test 4 || exit -1
do_test 6 || exit -1

! [ "$unload" = "1" -a -d /sys/module/quic ] || rmmod quic
