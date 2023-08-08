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
- Suppport both X509 Certficate and PSK mode

### TBD
- Keepalive Timer
- Connection ID Management
- Stream Enhanced Management
- Use up-call netlink to pass QUIC sockfd to kernel(NFS)

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
        # cd example/

        1.  With Certificate mode:
        # ./server 127.0.0.1 1234 ./keys/pkey.key ./keys/cert.crt
        # ./client 127.0.0.1 1234

        2.  With PSK mode:
        # ./server 127.0.0.1 1234 ./keys/psk.txt
        # ./client 127.0.0.1 1234 ./keys/pst.txt

  - If you want to use in-kernel QUIC without userspace handshake, try the
    sample_app where it's using the keys pre-defined in sample_context.h:

        # make sample_app
        # cd sample/

        # ./sample_server 127.0.0.1 1234 127.0.0.1 4321
        # ./sample_client 127.0.0.1 4321 127.0.0.1 1234

### usage:
   The handshake and module can be installed as a library by:

       # make install

   When using it, load quic module just like others:

       # modprobe quic

   in application c file such as in app.c (see example/ for how APIs are used):

       #include <netinet/quic.h>

   then build it by:

       # gcc app.c -o app -lquic
