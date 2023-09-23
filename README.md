# QUIC in Linux Kernel

## Overview

As mentioned in https://github.com/lxin/tls_hs#the-backgrounds: "some people may
argue that TLS handshake should stay in user space and use up-call to user space
in kernel to complete the handshake". This repo is to implement the idea. Note
that the main part of the QUIC protocol is still in Kernel space.

### userspace handshake based on ngtcp2 and gnutls
- Since only gnutls released version supports QUIC APIs, we choose
  ngtcp2 over gnutls instead of openssl as the userspace part.
- The userspace handshake part for the in-kernel QUIC is in [handshake.c](https://github.com/lxin/quic/tree/main/handshake.c).

### in-kernel QUIC implementation
- This is the main code part: it only processes SHORT packets when it is
  in connected state and passes LONG packets directly to userspace when
  it is in connecting/handshaking state.
- The kernel part for the rest of QUIC protocol is in [net/quic/](https://github.com/lxin/quic/tree/main/net/quic).

### Kernel Use like NFS and SMB over QUIC
- Send handshake request in kernel via [handshake netlink](https://docs.kernel.org/networking/tls-handshake.html) to Userspace.
- Integrate QUIC handshake in [ktls-utils](https://github.com/lxin/ktls-utils) for this.

## Implementation

### Completed
- Data (re)transmission and SACK
- Flow Control
- RTT Measurement
- Rekeying
- Connection Migration
- Congestion Control
- Support both X509 Certficate and PSK mode
- Handshake APIs for tlshd use (NFS)
- Connection ID Management
- Interoperability Testing with MSQUIC

### TBD
- Keepalive Timer
- Stream Enhanced Management
- IPv6 Support Needs to be Tested

## INSTALL

Note: The kernel and gnutls version should not be too old, the example below is on RHEL-9.

### build kernel module quic.ko
    # dnf install kernel-devel gcc
    # git clone https://github.com/lxin/quic.git
    # make module
    make -C /lib/modules/5.14.0-332.el9.x86_64/build M=/root/quic/net/quic modules
    make[1]: Entering directory '/usr/src/kernels/5.14.0-332.el9.x86_64'
      CC [M]  /root/quic/net/quic/protocol.o
      CC [M]  /root/quic/net/quic/socket.o
      CC [M]  /root/quic/net/quic/connection.o
      CC [M]  /root/quic/net/quic/stream.o
      CC [M]  /root/quic/net/quic/path.o
      CC [M]  /root/quic/net/quic/packet.o
      CC [M]  /root/quic/net/quic/frame.o
      CC [M]  /root/quic/net/quic/input.o
      CC [M]  /root/quic/net/quic/output.o
      CC [M]  /root/quic/net/quic/crypto.o
      CC [M]  /root/quic/net/quic/pnmap.o
      CC [M]  /root/quic/net/quic/timer.o
      CC [M]  /root/quic/net/quic/cong.o
      LD [M]  /root/quic/net/quic/quic.o
      MODPOST /root/quic/net/quic/Module.symvers
      CC [M]  /root/quic/net/quic/quic.mod.o
      LD [M]  /root/quic/net/quic/quic.ko
      BTF [M] /root/quic/net/quic/quic.ko
    Skipping BTF generation for /root/quic/net/quic/quic.ko due to unavailability of vmlinux
    make[1]: Leaving directory '/usr/src/kernels/5.14.0-332.el9.x86_64'
    modprobe udp_tunnel
    modprobe ip6_udp_tunnel
    insmod net/quic/quic.ko

    # lsmod |grep quic
    quic                   77824  0
    ip6_udp_tunnel         16384  1 quic
    udp_tunnel             24576  1 quic

### build and install lib ngtcp2
    (NOTE: you can skip this if you only use apps under sample/ directory)

    # dnf install -y autoconf automake pkg-config libtool gnutls-devel
    # git clone https://github.com/ngtcp2/ngtcp2.git
    # cd ngtcp2
    # autoreconf -i
    # ./configure --with-gnutls --prefix=/usr
    # make -j$(nproc) check
    # make install

### setup ca and generate certifcates
    # cd example/keys
    # ./ca_cert_pkey.sh
    # cd ../

### basic testing
  - After kernel quic module is installed, you can have some simple test and
    some tests with tlshd interface (see *APIs for tlshd* section):

        # cd example
        # make

        1.  With Certificate mode:
        # ./server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
        # ./client 127.0.0.1 1234

        2.  With PSK mode:
        # ./server 0.0.0.0 1234 ./keys/server-psk.txt
        # ./client 127.0.0.1 1234 ./keys/client-psk.txt

        3.  Testing tlshd interface with Certificate mode:
        # ./tlshd_server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
        # ./tlshd_client 127.0.0.1 1234 ./keys/client-key.pem ./keys/client-cert.pem server.test

        4.  Testing tlshd interface with PSK mode:
        # ./tlshd_server 0.0.0.0 1234 ./keys/server-psk.txt
        # ./tlshd_client 127.0.0.1 1234 ./keys/client-psk.txt

  - If you want to use in-kernel QUIC without userspace handshake, try the
    sample_app where it's using the keys pre-defined in sample_context.h:

        # cd sample/
        # make

        # ./sample_server 127.0.0.1 1234 127.0.0.1 4321
        # ./sample_client 127.0.0.1 4321 127.0.0.1 1234

  - See Interoperability Testing in *Interoperability Testing* section.

## USAGE:
### General use:

  - The handshake and module can be installed as a library by:

        # make install

  - When using it, load quic module just like others:

        # modprobe quic

  - in application c file such as in app.c (see example/ for how APIs are used):

        #include <netinet/quic.h>

      and it includes APIs:

        int quic_client_x509_handshake(int sockfd);
        int quic_server_x509_handshake(int sockfd, char *pkey, char *cert);

        int quic_client_psk_handshake(int sockfd, char *psk);
        int quic_server_psk_handshake(int sockfd, char *psk);

        int quic_sendmsg(int sockfd, const void *msg, size_t len, uint32_t sid, uint32_t flag);
        int quic_recvmsg(int sockfd, void *msg, size_t len, uint32_t *sid, uint32_t *flag);

  - then build it by:

        # gcc app.c -o app -lquic

### APIs for tlshd

(also included in netinet/quic.h)

    struct quic_handshake_parms {
    	uint32_t		timeout;	/* handshake timeout in milliseconds */
    
    	gnutls_privkey_t	privkey;	/* private key for x509 handshake */
    	gnutls_pcert_st		*cert;		/* certificate for x509 handshake */
    	char 			*peername;	/* - server name for client side x509 handshake or,
    						 * - psk identity name chosen during PSK handshake
    						 */
    	char			*names[10];	/* psk identifies in PSK handshake */
    	gnutls_datum_t		keys[10];	/* - psk keys in PSK handshake, or,
    						 * - certificates received in x509 handshake
    						 */
    	uint32_t		num_keys;	/* keys total numbers */
    };

    int quic_client_x509_tlshd(int sockfd, struct quic_handshake_parms *parms);
    int quic_server_x509_tlshd(int sockfd, struct quic_handshake_parms *parms);

    int quic_client_psk_tlshd(int sockfd, struct quic_handshake_parms *parms);
    int quic_server_psk_tlshd(int sockfd, struct quic_handshake_parms *parms);

## Interoperability Testing:

### build and run the test with MSQUIC
  - install msquic lib

        # yum install -y cmake
        # git clone --recursive https://github.com/microsoft/msquic.git
        # cd msquic
        # mkdir build && cd build
        # cmake -G 'Unix Makefiles' ..
        # cmake --build .
        # make install

  - run the 4 tests between msquic and lkquic (Linux Kernel QUIC in this repo):

        # cd test/
        # make

        1. msquic -> msquic:
        # ./msquic_test -server -cert_file:../example/keys/server-cert.pem -key_file:../example/keys/server-key.pem
        # time ./msquic_test -client -target:127.0.0.1

        2. lkquic -> msquic:
        # ./msquic_test -server -cert_file:../example/keys/server-cert.pem -key_file:../example/keys/server-key.pem
        # time ./lkquic_test client 127.0.0.1 1234

        3. msquic -> lkquic:
        # ./lkquic_test server 127.0.0.1 1234 ../example/keys/server-key.pem ../example/keys/server-cert.pem
        # time ./msquic_test -client -target:127.0.0.1

        4. lkquic -> lkquic:
        # ./lkquic_test server 127.0.0.1 1234 ../example/keys/server-key.pem ../example/keys/server-cert.pem
        # time ./lkquic_test client 127.0.0.1 1234

### build and run the tests from kernel space
  - build and install tlshd:

        # make install
        # git clone https://github.com/lxin/ktls-utils
        # cd ktls-utils
        # cat src/tlshd/tlshd.conf (setup certficates, for example)
          [authenticate.client]
          #x509.truststore= <pathname>
          x509.certificate=/root/quic_new/example/keys/client-cert.pem
          x509.private_key=/root/quic_new/example/keys/client-key.pem
          
          [authenticate.server]
          #x509.truststore= <pathname>
          x509.certificate=/root/quic_new/example/keys/server-cert.pem
          x509.private_key=/root/quic_new/example/keys/server-key.pem
        
        # ./autogen.sh
        # ./configure && make && make install
        # systemctl start tlshd

  - run the 4 tests between kernel and lk/msquic:

        # cd test/
        # make

        1. kernel -> lkquic
        # rmmod quic_test
        # ./lkquic_test server 127.0.0.1 1234 ../example/keys/server-key.pem ../example/keys/server-cert.pem
        # insmod ../net/quic/quic_test.ko

        2. kernel -> msquic
        # rmmod quic_test
        # ./msquic_test -server -cert_file:../example/keys/server-cert.pem -key_file:../example/keys/server-key.pem
        # insmod ../net/quic/quic_test.ko

        3. lkquic -> kernel
        # rmmod quic_test
        # insmod ../net/quic/quic_test.ko role=server
        # time ./lkquic_test client 127.0.0.1 1234

        4. msquic -> kernel
        # insmod net/quic/quic_test.ko role=server
        # time ./msquic_test -client -target:127.0.0.1
