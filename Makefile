all: module app sample_app
clean: module_clean app_clean sample_clean

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)/net/quic modules
	modprobe udp_tunnel
	modprobe ip6_udp_tunnel
	insmod net/quic/quic.ko
module_clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)/net/quic clean
	lsmod | grep -q quic && rmmod quic || :

sample_app:
	make -C sample
sample_clean:
	make -C sample clean

app:
	make -C example
app_clean:
	make -C example clean
