all: example_app
clean: example_clean

INCS = -I../net/quic/uapi/ -I../
LIBS = -lngtcp2_crypto_gnutls -lngtcp2 -lgnutls

example_app: client.c server.c tlshd_client.c tlshd_server.c ../handshake.c
	gcc client.c ../handshake.c -o client $(LIBS) $(INCS)
	gcc tlshd_client.c ../handshake.c -o tlshd_client $(LIBS) $(INCS)
	gcc server.c ../handshake.c -o server $(LIBS) $(INCS)
	gcc tlshd_server.c ../handshake.c -o tlshd_server $(LIBS) $(INCS)
example_clean:
	rm -rf client server tlshd_client tlshd_server
