all: module module_install app sample_app
clean: module_clean app_clean sample_clean

SRCS = lib/*.c
INCS = -Iinclude -Inet/quic/uapi/
LIBS = -lngtcp2_crypto_gnutls -lngtcp2 -lgnutls -lev -lpthread

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)/net/quic modules
module_install:
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

app: client.c server.c $(SRCS)
	lsmod | grep -q quic || gcc client.c $(SRCS) -o client $(LIBS) $(INCS)
	lsmod | grep -q quic && gcc -DIN_KERNEL_QUIC client.c $(SRCS) -o client $(LIBS) $(INCS) || :
	lsmod | grep -q quic || gcc server.c $(SRCS) -o server $(LIBS) $(INCS)
	lsmod | grep -q quic && gcc -DIN_KERNEL_QUIC server.c $(SRCS) -o server $(LIBS) $(INCS) || :
app_clean:
	rm -rf client server
