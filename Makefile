all: lib module
install: lib_install module_install
clean: lib_clean module_clean

lib: handshake/connection.c handshake/crypto.c handshake/connection.h
	gcc -fPIC handshake/connection.c handshake/crypto.c -shared -o handshake/libquic.so -Iinclude/uapi/ -lgnutls
lib_install: lib
	install -m 644 include/uapi/linux/quic.h /usr/include/linux
	install -m 644 handshake/quic.h /usr/include/netinet/quic.h
	install -m 644 handshake/libquic.so /usr/lib64
	install -m 644 handshake/libquic.pc /usr/lib64/pkgconfig
lib_clean:
	rm -rf handshake/libquic.so

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)/net/quic modules ROOTDIR=$(CURDIR) CONFIG_IP_QUIC=m CONFIG_IP_QUIC_TEST=m
module_install: module
	! [ -d /sys/module/quic_unit_test ] || rmmod quic_unit_test
	! [ -d /sys/module/quic_sample_test ] || rmmod quic_sample_test
	! [ -d /sys/module/quic ] || rmmod quic
	install -m 644 include/uapi/linux/quic.h /usr/include/linux
	[ -d /lib/modules/$(shell uname -r)/extra ] || mkdir /lib/modules/$(shell uname -r)/extra
	install -m 644 net/quic/quic.ko /lib/modules/$(shell uname -r)/extra
	install -m 644 net/quic/quic_unit_test.ko /lib/modules/$(shell uname -r)/extra
	! [ -f net/quic/quic_sample_test.ko ] || install -m 644 net/quic/quic_sample_test.ko /lib/modules/$(shell uname -r)/extra
	depmod -a
module_clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)/net/quic clean
	! [ -d /sys/module/quic ] || rmmod quic

uninstall:
	rm -rf /usr/include/linux/quic.h /usr/include/netinet/quic.h
	rm -rf /lib/modules/$(shell uname -r)/extra/quic.ko
	rm -rf /lib/modules/$(shell uname -r)/extra/quic_sample_test.ko
	rm -rf /lib/modules/$(shell uname -r)/extra/quic_unit_test.ko
	rm -rf /usr/lib64/libquic.so /usr/lib64/pkgconfig/libquic.pc
	! [ -d /sys/module/quic_unit_test ] || rmmod quic_unit_test
	! [ -d /sys/module/quic_sample_test ] || rmmod quic_sample_test
	! [ -d /sys/module/quic ] || rmmod quic
