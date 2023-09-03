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

### up-call netlink to pass QUIC sockfd to NFS (TBD)
- Pass the sockfd to Kernel via [handshake netlink](https://docs.kernel.org/networking/tls-handshake.html) for NFS use.
- May integrate the handshake code into [ktls-utils](https://github.com/oracle/ktls-utils) for this.

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

### TBD
- Keepalive Timer
- Connection ID Management
- Stream Enhanced Management

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

### testing
  - After kernel quic module is installed, then:

        # make app
        # cd example/keys
        # ./ca_cert_pkey.sh # (setup ca and certifcates)
        # cd ../

        1.  With Certificate mode:
        # ./server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
        # ./client 127.0.0.1 1234

        2.  With PSK mode:
        # ./server 0.0.0.0 1234 ./keys/server-psk.txt
        # ./client 127.0.0.1 1234 ./keys/client-psk.txt

  - You can also run the example for tlshd interface:

        1.  With Certificate mode:
        # ./tlshd_server 0.0.0.0 1234 ./keys/server-key.pem ./keys/server-cert.pem
        # ./tlshd_client 127.0.0.1 1234 ./keys/client-key.pem ./keys/client-cert.pem server.test

        2.  With PSK mode:
        # ./tlshd_server 0.0.0.0 1234 ./keys/server-psk.txt
        # ./tlshd_client 127.0.0.1 1234 ./keys/client-psk.txt

  - If you want to use in-kernel QUIC without userspace handshake, try the
    sample_app where it's using the keys pre-defined in sample_context.h:

        # make sample_app
        # cd sample/

        # ./sample_server 127.0.0.1 1234 127.0.0.1 4321
        # ./sample_client 127.0.0.1 4321 127.0.0.1 1234

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
    	char			*alpn;		/* alpn support */
    	uint32_t		timeout;	/* handshake timeout in seconds */
    
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
