# QUIC in Linux Kernel

## Overview

As mentioned in https://github.com/lxin/tls_hs#the-backgrounds: "some people may argue that TLS
handshake should stay in user space and use up-call to user space in kernel to complete the
handshake". This repo is to implement the idea. Note that the main part of the QUIC protocol
is still in Kernel space.

## Implementation

### General Idea

- **What's in Userspace**: Only TLS Handshake Messages processing and creating via gnutls,
these messages are sent and received via sendmsg/recvmsg() with crypto level in cmsg. See:
[handshake/](https://github.com/lxin/quic/tree/main/handshake).

- **What's in Kernel**: All QUIC protocol except TLS Handshake Messages processing and creating.
Instead of a ULP layer, it creates IPPROTO_QUIC type socket (similar to IPPROTO_MPTCP) running
over UDP TUNNEL. See: [net/quic/](https://github.com/lxin/quic/tree/main/net/quic).

- **How Kernel Consumers Use It**: Kernel users can send Handshake request from kernel via
[handshake netlink](https://docs.kernel.org/networking/tls-handshake.html) to Userspace. tlshd
in [ktls-utils](https://github.com/lxin/ktls-utils) will handle the handshake request for QUIC.

### Infrastructures

- Handshake:

        +-----------------------------------------------------------------------------------+
        |                               GNUTLS USER LIBRARY                                 |
        +---------+-+---------------------+-+------------------------+-+--------------------+
           TLS HANDSHAKE MSGS       TLS TRANSPORT PARAMS EXT     TLS SECRETS
           [sendmsg/recvmsg()       [setsockopt/getsockopt()     [setsockopt/getsockopt()
            with cmsg quic_          with optname QUIC_SOCKOPT_   with optname QUIC_SOCKOPT_
            handshake_info]          TRANSPORT_PARAM_EXT]         CRYPTO_SECRET]
                  | ^                     | ^                        | ^
        Userspace | |                     | |                        | |
        ----------+-+---------------------+-+------------------------+-+---------------------
        Kernel    | |                     | |                        | |
                  v |                     v |                        v |
            QUIC CRYPTO FRAMES       QUIC TRANSPORT PARAMS       QUIC KEYS
            [create or parse quic    [encode or decode quic      [derive quic key iv hp_key
             long packet and quic     tranport params from        for send/recv of handshake
             crypto frame]            tls tranport params ext]    and application data]
        +-----------------------------------------------------------------------------------+
        |    QUIC CONNECTION     |      PACKET      |      FRAME       |      CRYPTO        |
        +-----------------------------------------------------------------------------------+
        |                               UDP TUNNEL KERNEL APIs                              |
        +-----------------------------------------------------------------------------------+

- Post-Handshake:

           APPLICATION DATA                QUIC PRIMITIVES
           [sendmsg/recvmsg()              [setsockopt/getsockopt()
            with cmsg quic_                 with optname like QUIC_SOCKOPT
            stream_info]                    _KEY_UPDATE and _STREAM_RESET ...]
                  | ^                            | ^
        Userspace | |                            | |
        ----------+-+----------------------------+-+------------------------------
        Kernel    | |                            | |
                  v |                            v |
            QUIC STREAM FRAMES              QUIC CONTROL FRAMES
            [quic short packet and          [quic short packet and
             stream frame creating           corresponding ctrl frames
             and processing]                 creating and processing]
        +------------------------------------------------------------------------+
        | QUIC CONNECTION | STREAM | PACKET | FRAME | CRYPTO | FLOW | CONGESTION |
        +------------------------------------------------------------------------+
        |                           UDP TUNNEL KERNEL APIs                       |
        +------------------------------------------------------------------------+

### Features
#### most features from these RFCs are supported
- RFC9000 - *QUIC: A UDP-Based Multiplexed and Secure Transport*
- RFC9001 - *Using TLS to Secure QUIC*
- RFC9002 - *QUIC Loss Detection and Congestion Control*
- RFC9221 - *An Unreliable Datagram Extension to QUIC*
- RFC9287 - *Greasing the QUIC Bit*
- RFC9369 - *QUIC Version 2*
- Handshake APIs for tlshd Use - *NFS/SMB over QUIC*

#### some are still ongoing:
- Transport Error Codes for All Error Cases
- Performance Optimization

## INSTALL

### Build QUIC Kernel Module and Libquic:
    (IMPORTANT: please use the latest kernel (>=6.5) if you want to use QUIC from kernel space)

    Packages Required:
    - make autoconf automake libtool pkg-config
    - gnutls-devel / gnutls-dev
    - kernel-devel / linux-headers-$(uname -r)

    # cd ~/
    # git clone https://github.com/lxin/quic.git
    # cd quic/
    # pwd (e.g. /root/quic/)
    # ./autogen.sh
    # ./configure --prefix=/usr

- build the kernel quic module

      # make module
      # sudo make module_install

  **Or**, you can also integrate it in your kernel source code to build (e.g. /home/net-next/):

      # cp -r include net /home/net-next
      # cd /home/net-next/
      # sed -i 's@.*sctp.*@&\nobj-$(CONFIG_IP_QUIC)\t\t+= quic/@' net/Makefile
      # sed -i 's@.*sctp.*@&\nsource "net/quic/Kconfig"@' net/Kconfig

  Then build kernel with:

      CONFIG_IP_QUIC=m
      CONFIG_IP_QUIC_TEST=m

- build libquic for userspace handshake

      # make
      # sudo make install

- run selftests

      (NOTE: run tests to make sure all works well)
      # cd tests/
      # sudo make run

### Build and Install tlshd (For Kernel Consumer):
    (NOTE: you can skip this if you don't want to use QUIC in kernel space)

    Packages Required:
    - keyutils-libs-devel / libkeyutils-dev
    - glib2-devel / glib-2.0-dev
    - libnl3-devel / libnl-genl-3-dev

    (IMPORTANT: disable selinux, as selinux may stop quic.ko being loaded automatically and
                also not allow to use getpeername() in tlshd)
    # cd ~/
    # git clone https://github.com/lxin/ktls-utils
    # cd ktls-utils/
    # ./autogen.sh
    # ./configure --with-systemd
    # make
    # sudo make install

    (IMPORTANT: configure certficates, for testing you can use the certficates unders tests/keys/
                generated during running the tests, for example)
    # sudo \cp -vf src/tlshd/tlshd.conf /etc/tlshd.conf
    # sudo cat /etc/tlshd.conf
      ...
      [authenticate.client]
      #x509.truststore= <pathname>
      x509.certificate=/root/quic/tests/keys/client-cert.pem
      x509.private_key=/root/quic/tests/keys/client-key.pem
      
      [authenticate.server]
      #x509.truststore= <pathname>
      x509.certificate=/root/quic/tests/keys/server-cert.pem
      x509.private_key=/root/quic/tests/keys/server-key.pem

    # sudo systemctl enable tlshd
    # sudo systemctl restart tlshd
    (re-run the selftests in 'run selftests' section)

### Build and Install MSQUIC (Optional):
    (NOTE: you can skip this if you don't want to run the interoperability tests with MSQUIC)

    Packages Required:
    - cmake g++

    # cd ~/
    # git clone --recursive https://github.com/microsoft/msquic.git
    # cd msquic/
    # mkdir build && cd build/
    # cmake -G 'Unix Makefiles' ..
    # cmake --build .
    # sudo make install
    (re-run the selftests in 'run selftests' section)

## USAGE

### Simple APIs Use in User Space

  - these APIs are provided (see [tests/sample_test.c](https://github.com/lxin/quic/blob/main/tests/sample_test.c) for how APIs are used),
    and used as easily as TCP or SCTP socket, except with a handshake call(like kTLS):

                Client				    Server
             ------------------------------------------------------------------
             sockfd = socket(IPPROTO_QUIC)      listenfd = socket(IPPROTO_QUIC)
             bind(sockfd)                       bind(listenfd)
                                                listen(listenfd)
             connect(sockfd)
             quic_client_handshake()
                                                sockfd = accecpt(listenfd)
                                                quic_server_handshake()
          
             sendmsg(sockfd)                    recvmsg(sockfd)
             close(sockfd)                      close(sockfd)
                                                close(listenfd)

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

        /* quic_sendmsg() and quic_recvmsg() allow you to send and recv messages with
         * stream_id and stream_flags, they wrap sendmsg() and recvmsg().
         *
         * setsockopt() and getsockopt() can give you more control on QUIC use, show more details
         * in mandoc by # man quic, and see more examples in tests/func_test.c.
         */
        int quic_sendmsg(int sockfd, const void *msg, size_t len, uint64_t sid, uint32_t flag);
        int quic_recvmsg(int sockfd, void *msg, size_t len, uint64_t *sid, uint32_t *flag);

  - include the header file in c file like sample_test.c:

        #include <netinet/quic.h>

  - then build it by:

        # gcc sample_test.c -o sample_test -lquic

### APIs with more TLS Handshake Parameters

  - these APIs are provided (see [tests/perf_test.c](https://github.com/lxin/quic/blob/main/tests/perf_test.c#L349) for how APIs are used):

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

        int quic_client_handshake_parms(int sockfd, struct quic_handshake_parms *parms);
        int quic_server_handshake_parms(int sockfd, struct quic_handshake_parms *parms);

  - include the header file in c file like perf_test.c:

        #include <netinet/quic.h>

  - then build it by:

        # gcc perf_test.c -o perf_test -lquic -lgnutls

### Use in Kernel Space

NOTE: tlshd service must be installed and started, see
[build and install tlshd (For Kernel Consumer)](https://github.com/lxin/quic#build-and-install-tlshd-for-kernel-consumer)),
as it receives and handles the kernel handshake request for kernel sockets.

In kernel space, the use is pretty much like TCP sockets, except a extra handshake up-call.
(See [net/quic/sample_test.c](https://github.com/lxin/quic/blob/main/net/quic/sample_test.c) for examples)

            Client				    Server
         ---------------------------------------------------------------------------
         __sock_create(IPPROTO_QUIC, &sock)     __sock_create(IPPROTO_QUIC, &sock)
         kernel_bind(sock)                      kernel_bind(sock)
                                                kernel_listen(sock)
         kernel_connect(sock)
         tls_client_hello_x509(args:{sock})
                                                kernel_accept(sock, &newsock)
                                                tls_server_hello_x509(args:{newsock})
         
         kernel_sendmsg(sock)                   kernel_recvmsg(newsock)
         sock_release(sock)                     sock_release(newsock)
                                                sock_release(sock)


You can run the kernel test code as it shows in [Kernel Tests](https://github.com/lxin/quic/blob/main/tests/runtest.sh#L84)
part of tests/runtest.sh
