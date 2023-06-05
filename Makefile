all: module module_install app
clean: module_clean app_clean

app: client server

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)/net/quic modules
module_install:
	echo "file $(shell pwd)/net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control
	modprobe udp_tunnel
	modprobe ip6_udp_tunnel
	insmod net/quic/quic.ko
module_clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)/net/quic clean
	lsmod | grep -q quic && rmmod quic || :

SRCS = lib/*.c
LIBS = -lngtcp2_crypto_gnutls -lngtcp2 -lgnutls -lev -lpthread
INCS = -Iinclude

client: client.c $(SRCS)
	lsmod | grep -q quic || gcc client.c $(SRCS) -o client $(LIBS) $(INCS)
	lsmod | grep -q quic && gcc -DIN_KERNEL_QUIC client.c $(SRCS) -o client $(LIBS) $(INCS) || :
server: server.c $(SRCS)
	lsmod | grep -q quic || gcc server.c $(SRCS) -o server $(LIBS) $(INCS)
	lsmod | grep -q quic && gcc -DIN_KERNEL_QUIC server.c $(SRCS) -o server $(LIBS) $(INCS) || :
app_clean:
	rm -rf client server
