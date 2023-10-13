# QUIC in Linux Kernel

## Overview

As mentioned in https://github.com/lxin/tls_hs#the-backgrounds: "some people may argue that TLS
handshake should stay in user space and use up-call to user space in kernel to complete the
handshake". This repo is to implement the idea. Note that the main part of the QUIC protocol
is still in Kernel space.

## Implementation

### General Idea
- **Userspace Handshake based on ngtcp2 and gnutls**: Since only gnutls released version supports
QUIC APIs, we choose ngtcp2 over gnutls instead of openssl as the userspace part. The userspace
handshake part for the in-kernel QUIC is in
[handshake.c](https://github.com/lxin/quic/tree/main/handshake.c).

- **In-Kernel QUIC Implementation**: This is the main code part, and instead of creating a ULP
layer, it creates IPPROTO_QUIC socket(similar to IPPROTO_MPTCP) running over UDP TUNNEL, where
it only processes SHORT packets when it is in connected state and passes LONG packets directly
to userspace when it is in connecting/handshaking state. The kernel part for the rest of QUIC
protocol is in [net/quic/](https://github.com/lxin/quic/tree/main/net/quic).

- **Kernel Use like NFS and SMB over QUIC**: Handshake request will be sent from kernel via
[handshake netlink](https://docs.kernel.org/networking/tls-handshake.html) to Userspace. tlshd
in [ktls-utils](https://github.com/lxin/ktls-utils) will handle the handshake request for QUIC.

NOTE: [tests/simple_test.c](https://github.com/lxin/quic/blob/main/tests/sample_test.c) can
give you a better idea what context to be set into kernel after userspace handshake.

### Completed
- Data (re)transmission and SACK
- Flow Control
- RTT Measurement
- Rekeying
- Connection Migration
- Congestion Control
- Support both X509 Certificate and PSK mode
- Handshake APIs for tlshd use (NFS/SMB)
- Stream Management
- Connection ID Management
- Interoperability Testing with MSQUIC

### TBD
- Idle Connection Timer
- Enable More Cipher Suites.

## INSTALL

### Build and Install ngtcp2
    # dnf install -y autoconf automake pkg-config libtool gnutls-devel gcc
    # cd ~/
    # git clone https://github.com/ngtcp2/ngtcp2.git
    # cd ngtcp2/

    (IMPORTANT: use v0.18.0, as the latest version sends new connection id too early)
    # git checkout v0.18.0

    # autoreconf -i
    # ./configure --with-gnutls --prefix=/usr
    # make -j$(nproc) check
    # make install

### Build QUIC Kernel Module and Libquic:
    (IMPORTANT: please use the latest kernel (>=6.5) if you want to use QUIC from kernel space)

    # dnf install -y kernel-devel dwarves
    # cd ~/
    # git clone https://github.com/lxin/quic.git
    # cd quic/
    # pwd
    /root/quic (e.g.)

#### build the kernel quic module
    # make module
    make -C /lib/modules/6.6.0-rc1.nxt/build M=/root/quic/net/quic modules ROOTDIR=/root/quic CONFIG_IP_QUIC=m CONFIG_IP_QUIC_TEST=m
    make[1]: Entering directory '/media/net-next'
    warning: the compiler differs from the one used to build the kernel
      The kernel was built by: gcc (GCC) 8.5.0 20210514 (Red Hat 8.5.0-4)
      You are using:           gcc (GCC) 11.4.1 20230605 (Red Hat 11.4.1-2)
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
      CC [M]  /root/quic/net/quic/test/test.o
      LD [M]  /root/quic/net/quic/quic_test.o
      MODPOST /root/quic/net/quic/Module.symvers
      CC [M]  /root/quic/net/quic/quic.mod.o
      LD [M]  /root/quic/net/quic/quic.ko
      BTF [M] /root/quic/net/quic/quic.ko
      CC [M]  /root/quic/net/quic/quic_test.mod.o
      LD [M]  /root/quic/net/quic/quic_test.ko
      BTF [M] /root/quic/net/quic/quic_test.ko
    make[1]: Leaving directory '/media/net-next'

    # make module_install
    install -m 644 include/uapi/linux/quic.h /usr/include/linux
    install -m 644 net/quic/quic.ko -d /lib/modules/6.6.0-rc1.nxt/extra/
    depmod -a

  **Or**, you can also integrate it in your kernel source code to build (e.g. /home/net-next/):

    # cp -r include net /home/net-next
    # cd /home/net-next/
    # sed -i 's@.*sctp.*@&\nobj-$(CONFIG_IP_QUIC)\t\t+= quic/@' net/Makefile
    # sed -i 's@.*sctp.*@&\nsource "net/quic/Kconfig"@' net/Kconfig

    Then build kernel with:

      CONFIG_IP_QUIC=m

#### build libquic for userspace handshake
    # make lib
    gcc -fPIC handshake.c -shared -o libquic.so -Iinclude/uapi/ -lngtcp2_crypto_gnutls -lngtcp2 -lgnutls

    # make lib_install
    install -m 644 handshake.h /usr/include/netinet/quic.h
    install -m 644 libquic.so /usr/lib64
    install -m 644 libquic.pc /usr/lib64/pkgconfig

#### run selftests
    (IMPORTANT: run tests to make sure all works well)

    # cd tests/
    # make
    gcc func_test.c -o func_test -lquic
    gcc perf_test.c -o perf_test -lquic -lgnutls
    gcc sample_test.c -o sample_test

    # make run
    ...

### Build and Install tlshd (For Kernel Use):
    (NOTE: you can skip this if you don't want to use QUIC from kernel)

    # dnf install -y keyutils-libs-devel glib2-devel libnl3-devel

    (IMPORTANT: disable selinux, as selinux may stop quic.ko being loaded automatically and
                also not allow to use getpeername() in tlshd)
    # setenforce 0
    # semodule -B
    # grubby --update-kernel ALL --args selinux=0

    # cd ~/
    # git clone https://github.com/lxin/ktls-utils
    # cd ktls-utils/
    # ./autogen.sh
    # ./configure --with-systemd
    # make
    # make install

    (IMPORTANT: configure certficates, for testing you can use the certficates unders tests/keys/
                generated during running the tests, for example)
    # cat /etc/tlshd.conf
      [authenticate.client]
      #x509.truststore= <pathname>
      x509.certificate=/root/quic/tests/keys/client-cert.pem
      x509.private_key=/root/quic/tests/keys/client-key.pem
      
      [authenticate.server]
      #x509.truststore= <pathname>
      x509.certificate=/root/quic/tests/keys/server-cert.pem
      x509.private_key=/root/quic/tests/keys/server-key.pem

    # systemctl enable tlshd
    # systemctl restart tlshd

### Build and Install MSQUIC (Optional For Testing):
    (NOTE: you can skip this if you don't want to run the interoperability tests with MSQUIC)

    # dnf install -y cmake
    # cd ~/
    # git clone --recursive https://github.com/microsoft/msquic.git
    # cd msquic/
    # mkdir build && cd build/
    # cmake -G 'Unix Makefiles' ..
    # cmake --build .
    # make install

## USAGE

### Use In User Space

  - these APIs are provided (see [tests/func_test.c](https://github.com/lxin/quic/blob/main/tests/func_test.c) for how APIs are used):

        int quic_client_x509_handshake(int sockfd);
        int quic_server_x509_handshake(int sockfd, char *pkey, char *cert);

        int quic_client_psk_handshake(int sockfd, char *psk);
        int quic_server_psk_handshake(int sockfd, char *psk);

        int quic_sendmsg(int sockfd, const void *msg, size_t len, uint32_t sid, uint32_t flag);
        int quic_recvmsg(int sockfd, void *msg, size_t len, uint32_t *sid, uint32_t *flag);

  - include the header file in func_test.c:

        #include <netinet/quic.h>

  - then build it by:

        # gcc func_test.c -o func_test -lquic

### APIs for tlshd in ktls-utils

  - these APIs are provided (see [tests/perf_test.c](https://github.com/lxin/quic/blob/main/tests/perf_test.c) for how APIs are used):

        struct quic_handshake_parms {
            uint32_t		timeout;	/* handshake timeout in milliseconds */

            gnutls_privkey_t	privkey;	/* private key for x509 handshake */
            gnutls_pcert_st	*cert;		/* certificate for x509 handshake */
            char 		*peername;	/* - server name for client side x509 handshake or,
            					 * - psk identity name chosen during PSK handshake
            					 */
            char		*names[10];	/* psk identifies in PSK handshake */
            gnutls_datum_t	keys[10];	/* - psk keys in PSK handshake, or,
            					 * - certificates received in x509 handshake
            					 */
            uint32_t		num_keys;	/* keys total numbers */
        };

        int quic_client_x509_tlshd(int sockfd, struct quic_handshake_parms *parms);
        int quic_server_x509_tlshd(int sockfd, struct quic_handshake_parms *parms);

        int quic_client_psk_tlshd(int sockfd, struct quic_handshake_parms *parms);
        int quic_server_psk_tlshd(int sockfd, struct quic_handshake_parms *parms);

  - include the header file in perf_test.c:

        #include <netinet/quic.h>

  - then build it by:

        # gcc perf_test.c -o perf_test -lquic -lgnutls

### Use in Kernel Space

NOTE: tlshd service must be installed and started, see
[build and install tlshd (For Kernel Use)](https://github.com/lxin/quic#build-and-install-tlshd-for-kernel-use)),
as it receives and handles the kernel handshake request for kernel sockets.

In kernel space, the use is pretty much like TCP sockets, other than a extra handshake up-call.
(See [net/quic/test/test.c](https://github.com/lxin/quic/blob/main/net/quic/test/test.c) for examples)

You can run the kernel test code as it shows in [Kernel Tests](https://github.com/lxin/quic/blob/main/tests/runtest.sh#L72)
part of tests/runtest.sh
