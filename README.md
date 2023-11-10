# QUIC in Linux Kernel

## Overview

As mentioned in https://github.com/lxin/tls_hs#the-backgrounds: "some people may argue that TLS
handshake should stay in user space and use up-call to user space in kernel to complete the
handshake". This repo is to implement the idea. Note that the main part of the QUIC protocol
is still in Kernel space.

## Implementation

### General Idea
- **Userspace Handshake with gnutls**: Since gnutls released version supports QUIC APIs, we
choose gnutls library and reuse some code from ngtcp2 as the userspace part. The userspace
handshake part for the in-kernel QUIC is in
[handshake/](https://github.com/lxin/quic/tree/main/handshake).

- **In-Kernel QUIC Implementation**: This is the main code part, and instead of creating a ULP
layer, it creates IPPROTO_QUIC socket(similar to IPPROTO_MPTCP) running over UDP TUNNEL, where
it only processes SHORT packets when it is in connected state and passes LONG packets directly
to userspace when it is in connecting/handshaking state. The kernel part for the rest of QUIC
protocol is in [net/quic/](https://github.com/lxin/quic/tree/main/net/quic).

- **Kernel Consumer like NFS and SMB over QUIC**: Handshake request will be sent from kernel via
[handshake netlink](https://docs.kernel.org/networking/tls-handshake.html) to Userspace. tlshd
in [ktls-utils](https://github.com/lxin/ktls-utils) will handle the handshake request for QUIC.

NOTE: [tests/simple_test.c](https://github.com/lxin/quic/blob/main/tests/sample_test.c) can
give you a better idea what context to be set into kernel after userspace handshake.

### Completed
- Data (re)transmission and SACK *(rfc9000)*
- Flow Control *(rfc9000)*
- Stream and Connection ID Management *(rfc9000)*
- Connection Migration *(rfc9000)*
- Rekeying *(rfc9001)*
- Support All Four Ciphers *(rfc9001)*
- Both X509 Certificate and PSK modes *(rfc9001)*
- RTT Measurement *(rfc9002)*
- Congestion Control *(rfc9002)*
- Unreliable Datagram Extension *(rfc9221)*
- Handshake APIs for tlshd Use *(NFS/SMB over QUIC)*
- Interoperability Testing with MSQUIC

### TBD
- Address Verify in Handshake
- Stateless Reset (rfc9000#name-stateless-reset)
- Nick suggests moving Long Packets to Kernel module

## INSTALL

### Build QUIC Kernel Module and Libquic:
    (IMPORTANT: please use the latest kernel (>=6.5) if you want to use QUIC from kernel space)

    # dnf install -y kernel-devel dwarves gnutls-devel gcc
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
    gcc -fPIC handshake/*.c -shared -o handshake/libquic.so -Iinclude/uapi/ -lgnutls

    # make lib_install
    install -m 644 handshake/quic.h /usr/include/netinet/quic.h
    install -m 644 handshake/libquic.so /usr/lib64
    install -m 644 handshake/libquic.pc /usr/lib64/pkgconfig

#### run selftests
    (NOTE: run tests to make sure all works well)

    # cd tests/
    # make
    gcc func_test.c -o func_test -lquic
    gcc perf_test.c -o perf_test -lquic -lgnutls
    gcc sample_test.c -o sample_test

    # make run
    ...

### Build and Install tlshd (For Kernel Consumer):
    (NOTE: you can skip this if you don't want to use QUIC in kernel space)

    # dnf install -y automake keyutils-libs-devel glib2-devel libnl3-devel

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
      ...
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

### Simple APIs Use in User Space

  - these APIs are provided (see [tests/func_test.c](https://github.com/lxin/quic/blob/main/tests/func_test.c#L2084) for how APIs are used),
    and used as easily as TCP or SCTP socket, except with a handshake call(like kTLS):

                Client				    Server
             ------------------------------------------------------------------
             sockfd = socket(IPPROTO_QUIC)	listenfd = socket(IPPROTO_QUIC)
             bind(sockfd)			bind(listenfd)
             					listen(listenfd)
             connect(sockfd)
             					sockfd = accecpt(listenfd)
             quic_client_handshake()		quic_server_handshake()
          
             sendmsg(sockfd)			recvmsg(sockfd);
             close(sockfd)			close(sockfd)

        /* PSK mode:
         * - pkey_file is psk file
         * - cert_file is null
         *
         * Certificate mode:
         * - pkey_file is private key file, can be null for client
         * - cert_file is certificate file, can be null for client
         */
        int quic_client_handshake(int sockfd, char *pkey_file, char *cert_file);
        int quic_server_handshake(int sockfd, char *pkey_file, char *cert_file);

        /* quic_sendmsg() and quic_recvmsg() allow you to send and recv message with stream_id
         * and stream_flags, they wrap sendmsg() and recvmsg().
         *
         * setsockopt() and getsockopt() can give you more control on QUIC use, see func_test
         * more details.
         */
        int quic_sendmsg(int sockfd, const void *msg, size_t len, uint64_t sid, uint32_t flag);
        int quic_recvmsg(int sockfd, void *msg, size_t len, uint64_t *sid, uint32_t *flag);

  - include the header file in func_test.c:

        #include <netinet/quic.h>

  - then build it by:

        # gcc func_test.c -o func_test -lquic

### APIs with more TLS Handshake Paramerters

  - these APIs are provided (see [tests/perf_test.c](https://github.com/lxin/quic/blob/main/tests/perf_test.c#L349) for how APIs are used):

        struct quic_handshake_parms {
        	uint32_t		timeout;	/* handshake timeout in milliseconds */
        
        	gnutls_privkey_t	privkey;	/* private key for x509 handshake */
        	gnutls_pcert_st		*cert;		/* certificate for x509 handshake */
        	char 			*peername;	/* - server name for client side x509 handshake or,
        						 * - psk identity name chosen during PSK handshake
        						 */
        	uint8_t			cert_req;	/* certificat request, server only
        						 * 0: IGNORE, 1: REQUEST, 2: REQUIRE
        						 */
        	char			*names[10];	/* psk identifies in PSK handshake */
        	gnutls_datum_t		keys[10];	/* - psk keys in PSK handshake, or,
        						 * - certificates received in x509 handshake
        						 */
        	uint32_t		num_keys;	/* keys total numbers */
        };

        int quic_client_handshake_parms(int sockfd, struct quic_handshake_parms *parms);
        int quic_server_handshake_parms(int sockfd, struct quic_handshake_parms *parms);

  - include the header file in perf_test.c:

        #include <netinet/quic.h>

  - then build it by:

        # gcc perf_test.c -o perf_test -lquic -lgnutls

### Use in Kernel Space

NOTE: tlshd service must be installed and started, see
[build and install tlshd (For Kernel Consumer)](https://github.com/lxin/quic#build-and-install-tlshd-for-kernel-consumer)),
as it receives and handles the kernel handshake request for kernel sockets.

In kernel space, the use is pretty much like TCP sockets, except a extra handshake up-call.
(See [net/quic/test/test.c](https://github.com/lxin/quic/blob/main/net/quic/test/test.c) for examples)

You can run the kernel test code as it shows in [Kernel Tests](https://github.com/lxin/quic/blob/main/tests/runtest.sh#L84)
part of tests/runtest.sh
