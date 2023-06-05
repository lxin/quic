# QUIC in Linux Kernel

## Overview

As mentioned in https://github.com/lxin/tls_hs#the-backgrounds: "some people may
argue that TLS handshake should stay in user space and use up-call to user space
in kernel to complete the handshake". The repo is to implement the idea. Note
that the main part of the QUIC protocol is still in Kernel space.

### posix-like QUIC APIs use based on ngtcp2 and gnutls
- Since only gnutls released version supports QUIC APIs, we choose
  ngtcp2 over gnutls instead of openssl as the userspace part.

### in-kernel QUIC implementation (Prototype)
- The userspace handshake part for the in-kernel QUIC in [lib/](https://github.com/lxin/quic/tree/main/lib).
- The kernel part for the rest of QUIC protocol is in [net/quic/](https://github.com/lxin/quic/tree/main/net/quic).

### up-call netlink to pass QUIC sockfd to NFS (TBD)
- Pass the sockfd to Kernel via 'handshake' netlink for NFS use.
  (Base on https://docs.kernel.org/networking/tls-handshake.html)

## Implementation

### Completed
- Data (re)transmission and SACK
- Flow Control
- RTT Measurement
- Congestion Control (adding)

### TBD
- Use up-call netlink to pass QUIC sockfd to kernel(NFS)
- Rekeying
- Connection Migration
- Connection ID and Path and Stream Enhanced Management

## INSTALL

Note: The kernel and gnutls version should not be too old, the example below is on RHEL-9.

### build and install lib ngtcp2
    # dnf install -y autoconf automake pkg-config libtool gnutls-devel
    # git clone https://github.com/ngtcp2/ngtcp2.git
    # cd ngtcp2
    # autoreconf -i
    # ./configure --with-gnutls --prefix=/usr
    # make -j$(nproc) check
    # make install

### build kernel module quic.ko
    # dnf install kernel-devel gcc libev-devel
    # git clone https://github.com/lxin/quic.git
    # make module
    make -C /lib/modules/5.14.0-327.el9.x86_64/build M=/root/quic/net/quic modules
    make[1]: Entering directory '/usr/src/kernels/5.14.0-327.el9.x86_64'
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
      LD [M]  /root/quic/net/quic/quic.o
      MODPOST /root/quic/net/quic/Module.symvers
      CC [M]  /root/quic/net/quic/quic.mod.o
      LD [M]  /root/quic/net/quic/quic.ko
      BTF [M] /root/quic/net/quic/quic.ko
    Skipping BTF generation for /root/quic/net/quic/quic.ko due to unavailability of vmlinux
    make[1]: Leaving directory '/usr/src/kernels/5.14.0-327.el9.x86_64'

    # make module_install
    echo "file /root/quic/net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control
    modprobe udp_tunnel
    modprobe ip6_udp_tunnel
    insmod net/quic/quic.ko

    # lsmod |grep quic
    quic                   77824  0
    ip6_udp_tunnel         16384  1 quic
    udp_tunnel             24576  1 quic

### testing
  - After kernel quic module is installed, then:

        # make app
        # ./server 127.0.0.1 1234 ./keys/pkey.key ./keys/cert.crt
        # ./client 127.0.0.1 1234 ./keys/pkey.key ./keys/cert.crt

  - If you want use ngtcp2 without in-kernel QUIC:

        # make clean
        # make app
        # ./server 127.0.0.1 1234 ./keys/pkey.key ./keys/cert.crt
        # ./client 127.0.0.1 1234 ./keys/pkey.key ./keys/cert.crt
