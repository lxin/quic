all: msquic_test lkquic_test

INCS = -I../net/quic/uapi/ -I../
LIBS = -lngtcp2_crypto_gnutls -lngtcp2 -lgnutls

lkquic_test: lkquic_test.c ../handshake.c
	gcc lkquic_test.c ../handshake.c -o lkquic_test $(INCS) $(LIBS)
msquic_test: msquic_test.c
	g++ msquic_test.c -o msquic_test -lmsquic -Wl,-rpath=/usr/local/lib
clean:
	rm msquic_test lkquic_test
