all: lib module app sample_app
clean: lib_clean module_clean app_clean sample_clean

install: lib module
	install -m 644 net/quic/quic.ko /lib/modules/$(shell uname -r)/extra
	install -m 644 net/quic/uapi/linux/quic.h /usr/include/linux
	install -m 644 handshake.h /usr/include/netinet/quic.h
	install -m 644 libquic.so /usr/lib64
	install -m 644 libquic.pc /usr/lib64/pkgconfig
	depmod -a
uninstall:
	lsmod | grep -q quic && rmmod quic || :
	rm -rf /usr/include/linux/quic.h /usr/include/netinet/quic.h
	rm -rf /lib/modules/$(shell uname -r)/extra/quic.ko
	rm -rf /usr/lib64/libquic.so /usr/lib64/pkgconfig/libquic.pc
	depmod -a

INCS = -Inet/quic/uapi/
LIBS = -lngtcp2_crypto_gnutls -lngtcp2 -lgnutls
lib: handshake.c
	gcc -fPIC handshake.c -shared -o libquic.so $(INCS) $(LIBS)
lib_clean:
	rm -rf libquic.so

module:
	lsmod | grep -q quic && rmmod quic || :
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
