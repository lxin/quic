# QUIC in Linux Kernel

## Introduction

As mentioned in https://github.com/lxin/tls_hs#the-backgrounds: "some people may argue that TLS
handshake should stay in user space and use up-call to user space in kernel to complete the
handshake". This repo is to implement the idea. Note that the main part of the QUIC protocol
is still in Kernel space.

There are several compelling reasons for implementing in-kernel QUIC:
- Meeting the needs of kernel consumers like SMB and NFS.
- Standardizing socket APIs, including essential operations such as listen, accept,
  connect, sendmsg, recvmsg, close, get/setsockopt and getsock/peername().
- Incorporating ALPN matching within the kernel, efficiently directing incoming
  requests to relevant applications across different processes based on ALPN.
- Minimizing data duplication by utilizing zero-copy techniques like sendfile().
- Facilitating the crypto offloading in NICs to further enhance performance.
- Addressing interoperability issues from the variety of userland QUIC implementations.

## Implementation

### General Idea

- **What's in Userspace**: Only raw TLS Handshake Messages processing and creating via gnutls.
These messages are sent and received via sendmsg/recvmsg() with crypto level in cmsg. See:
[libquic/](https://github.com/lxin/quic/tree/main/libquic).

- **What's in Kernel**: All QUIC protocol except TLS Handshake Messages processing and creating.
Instead of a ULP layer, it creates IPPROTO_QUIC type socket (similar to IPPROTO_MPTCP and no
protocol number needed from IANA) running over UDP TUNNELs. See:
[modules/net/quic/](https://github.com/lxin/quic/tree/main/modules/net/quic).

- **How Kernel Consumers Use It**: Kernel users can send Handshake request from kernel via
[handshake netlink](https://docs.kernel.org/networking/tls-handshake.html) to Userspace. tlshd
in [ktls-utils](https://github.com/lxin/ktls-utils) will handle the handshake request for QUIC.

### Infrastructures

- Handshake Archtechiture:

      +------+  +------+
      | APP1 |  | APP2 | ...
      +------+  +------+
      +--------------------------------------------+
      |            libquic (gnutls)                |<----------+
      |  {quic_handshake_server/client/param()}    |           |
      +--------------------------------------------+  +------------------+
       {send/recvmsg()}       {set/getsockopt()}      |tlshd (ktls-utils)|
       [CMSG handshake_info]  [SOCKOPT_CRYPTO_SECRET] +------------------+
                              [SOCKOPT_TRANSPORT_PARAM_EXT]
                  | ^                    | ^                   | ^
      Userspace   | |                    | |                   | |
      ------------|-|--------------------|-|-------------------|-|------
      Kernel      | |                    | |                   | |
                  v |                    v |                   v |
      +---------------------------------------------+    +-------------+
      | socket (IPPRTOTO_QUIC) |      protocol      |<-+ | handshake   |
      +---------------------------------------------+  | | netlink APIs|
      | stream | connection_id | cong | path |timer |  | +-------------+
      +---------------------------------------------+  |    |      |
      |   packet  |   frame  |  crypto   |   pnmap  |  | +-----+ +-----+
      +---------------------------------------------+  | |     | |     |
      |         input        |       output         |  |-| SMB | | NFS |..
      +---------------------------------------------+  | |     | |     |
      |                UDP tunnels                  |  | +-----+ +--+--+
      +---------------------------------------------+  +------------|

- Application Data Archtechiture:

      +------+  +------+
      | APP1 |  | APP2 | ...
      +------+  +------+
        {send/recvmsg()}         {set/getsockopt()}
        [CMSG stream_info]       [SOCKOPT_KEY_UPDATE]
                                 [SOCKOPT_CONNECTION_MIGRATION]
                                 [SOCKOPT_STREAM_OPEN/RESET/STOP_SENDING]
                                 [...]
                | ^                    | ^
      Userspace | |                    | |
      ----------|-|--------------------|-|----------------
      Kernel    | |                    | |
                v |                    v |
      +---------------------------------------------+
      | socket (IPPRTOTO_QUIC) |      protocol      |<-+ {kernel_}
      +---------------------------------------------+  | {send/recvmsg()}
      | stream | connection_id | cong | path |timer |  | {set/getsockopt()}
      +---------------------------------------------+  |
      |   packet  |   frame  |  crypto   |   pnmap  |  | +-----+ +-----+
      +---------------------------------------------+  | |     | |     |
      |         input        |       output         |  |-| SMB | | NFS |..
      +---------------------------------------------+  | |     | |     |
      |                UDP tunnels                  |  | +-----+ +--+--+
      +---------------------------------------------+  +------------|

### Features
- Fundamental support for the following RFCs
  - RFC9000 - *QUIC: A UDP-Based Multiplexed and Secure Transport*
  - RFC9001 - *Using TLS to Secure QUIC*
  - RFC9002 - *QUIC Loss Detection and Congestion Control*
  - RFC9221 - *An Unreliable Datagram Extension to QUIC*
  - RFC9287 - *Greasing the QUIC Bit*
  - RFC9368 - *Compatible Version Negotiation for QUIC*
  - RFC9369 - *QUIC Version 2*
  - Handshake APIs for tlshd Use - *NFS/SMB over QUIC*

- Next step
  - Submit QUIC module to upstream kernel and libquic to gnutls library.
  - Create an Internet Draft For QUIC Sockets API Extensions.
  - Implement HW crypto offloading infrastructure.

## INSTALL

### Build QUIC Kernel Module and Libquic:
Both QUIC Kernel Module and Libquic can be built and installed simply by the commands below:

    Packages Required: (kernel_version >= 5.14)
    - make autoconf automake libtool pkg-config
    - gnutls-devel / gnutls-dev
    - kernel-devel / linux-headers-$(uname -r)

    # cd /home/lxin
    # git clone https://github.com/lxin/quic.git
    # cd quic/
    # ./autogen.sh
    # ./configure --prefix=/usr
    # make
    # sudo make install
    # sudo make check (optional, run selftests)

For these who want to integrate QUIC modules into kernel source code (e.g. /home/lxin/net-next/),
follow the instruction below to build and install kernel first, then the commands
above will skip QUIC modules building and use the one provided by kernel.

    # cp -r modules/include modules/net /home/lxin/net-next
    # cd /home/lxin/net-next/
    # sed -i 's@.*sctp.*@&\nobj-$(CONFIG_IP_QUIC)\t\t+= quic/@' net/Makefile
    # sed -i 's@.*sctp.*@&\nsource "net/quic/Kconfig"@' net/Kconfig

    Then build kernel with:

    CONFIG_IP_QUIC=m
    CONFIG_IP_QUIC_TEST=m

### Build and Install tlshd (For Kernel Consumer):
    Packages Required:
    - glib2-devel / glib-2.0-dev
    - libnl3-devel / libnl-genl-3-dev
    - keyutils keyutils-libs-devel / libkeyutils-dev

    # cd /home/lxin
    # git clone https://github.com/lxin/ktls-utils
    # cd ktls-utils/
    # ./autogen.sh
    # ./configure --with-systemd
    # make
    # sudo make install

    # sudo install -m 644 src/tlshd/tlshd.conf /etc/tlshd.conf
    # sudo vim /etc/tlshd.conf
      ...
      [authenticate]
      keyrings=quic

      [authenticate.client]
      x509.truststore= /home/lxin/quic/tests/keys/ca-cert.pem
      x509.certificate=/home/lxin/quic/tests/keys/client-cert.pem
      x509.private_key=/home/lxin/quic/tests/keys/client-key.pem

      [authenticate.server]
      x509.truststore= /home/lxin/quic/tests/keys/ca-cert.pem
      x509.certificate=/home/lxin/quic/tests/keys/server-cert.pem
      x509.private_key=/home/lxin/quic/tests/keys/server-key.pem

    # sudo systemctl enable tlshd
    # sudo systemctl restart tlshd

    # cd /home/lxin/quic
    # sudo make check (optional, re-run selftests)

### Build and Install iperf (For performance tests):
    # git clone https://github.com/lxin/iperf.git
    # cd iperf/
    # ./bootstrap.sh
    # ./configure --prefix=/usr
    # make
    # sudo make install

QUIC vs kTLS iperf testing over 100G physical NIC with different packet size and MTU:

    On server:
    # iperf3 -s --pkey /home/lxin/quic/tests/keys/server-key.pem  \
                --cert /home/lxin/quic/tests/keys/server-cert.pem

    On client:
    # iperf3 -c $SERVER_IP --quic -l $PACKET_LEN

    UNIT        size:1024      size:4096      size:16384     size:65536
    Gbits/sec   QUIC | kTLS    QUIC | kTLS    QUIC | kTLS    QUIC | kTLS
    --------------------------------------------------------------------
    mtu:1500    1.67 | 2.16    3.04 | 5.04    3.49 | 7.84    3.83 | 7.95
    no GSO           | 1.73         | 3.12         | 4.05         | 4.28
    --------------------------------------------------------------------
    mtu:9000    2.17 | 2.41    5.47 | 6.19    6.45 | 8.66    7.48 | 8.90
    no GSO           | 2.30         | 5.69         | 8.66         | 8.82

QUIC (disable\_1rtt\_encryption) vs TCP iperf testing over 100G physical NIC with
different packet size and MTU:

    On server:
    # iperf3 -s --pkey /home/lxin/quic/tests/keys/server-key.pem  \
                --cert /home/lxin/quic/tests/keys/server-cert.pem --no-cryption

    On client:
    # iperf3 -c $SERVER_IP --quic -l $PACKET_LEN --no-cryption

    UNIT        size:1024      size:4096      size:16384     size:65536
    Gbits/sec   QUIC | TCP     QUIC | TCP     QUIC | TCP     QUIC | TCP
    --------------------------------------------------------------------
    mtu:1500    2.17 | 2.49    3.59 | 8.36    6.09 | 15.1    6.92 | 16.2
    no GSO           | 2.50         | 4.12         | 4.86         | 5.04
    --------------------------------------------------------------------
    mtu:9000    2.47 | 2.54    7.66 | 7.97    14.7 | 20.3    19.1 | 31.3
    no GSO           | 2.51         | 8.34         | 18.3         | 22.3

Note kTLS testing is using iperf from https://github.com/Mellanox/iperf_ssl, and
the only way to disable TCP GSO is to remove sk_is_tcp() check in sk_setup_caps()
and bring sk_can_gso() back in kernel code.

As the test data shows, the TCP GSO contributes to performance a lot for TCP and
kTLS with mtu 1500 and large msgs. With TCP GSO disabled, the small performance
gap between QUIC and kTLS, QUIC with disable_1rtt_encryption and TCP is caused by:

- QUIC has an extra copy on TX path.
- QUIC has an extra encryption for header protection.
- QUIC has a longer header for the stream DATA.

## USAGE

Similar to TCP and SCTP, a typical server and client use the following system
call sequence to communicate:

       Client				    Server
    ------------------------------------------------------------------
    sockfd = socket(IPPROTO_QUIC)      listenfd = socket(IPPROTO_QUIC)
    bind(sockfd)                       bind(listenfd)
                                       listen(listenfd)
    connect(sockfd)
    quic_client_handshake(sockfd)
                                       sockfd = accecpt(listenfd)
                                       quic_server_handshake(sockfd, cert)

    sendmsg(sockfd)                    recvmsg(sockfd)
    close(sockfd)                      close(sockfd)
                                       close(listenfd)

This section shows you the basic usage of QUIC, you can get more details via man page:

    # man quic

### Basic APIs Use in User Space

- these APIs are provided (see [tests/sample_test.c](https://github.com/lxin/quic/blob/main/tests/sample_test.c) for how APIs are used):

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
       */
      ssize_t quic_sendmsg(int sockfd, const void *msg, size_t len, uint64_t sid, uint32_t flag);
      ssize_t quic_recvmsg(int sockfd, void *msg, size_t len, uint64_t *sid, uint32_t *flag);

- include the header file in c file like sample_test.c:

      #include <netinet/quic.h>

- then build it by:

      # gcc sample_test.c -o sample_test -lquic

### Advanced APIs with more TLS Handshake Parameters

- these APIs are provided (see [tests/perf_test.c](https://github.com/lxin/quic/blob/main/tests/perf_test.c#L349) for how APIs are used):

      struct quic_handshake_parms {
          uint32_t           timeout;    /* handshake timeout in milliseconds */

          gnutls_privkey_t   privkey;    /* private key for x509 handshake */
          gnutls_pcert_st    *cert;      /* certificate for x509 handshake */
          char               *cafile;    /* system ca is used if not set */
          char               *peername;  /* - server name for client side x509 handshake or,
                                          * - psk identity name chosen during PSK handshake
                                          */
          char               *names[10]; /* psk identifies in PSK handshake */
          gnutls_datum_t     keys[10];   /* - psk keys in PSK handshake, or,
                                          * - certificates received in x509 handshake
                                          */
          uint32_t           num_keys;   /* keys total numbers */
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
(See [modules/net/quic/sample_test.c](https://github.com/lxin/quic/blob/main/modules/net/quic/sample_test.c) for examples)

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

You can run the kernel test code as it shows in tlshd_tests() of [tests/runtest.sh](https://github.com/lxin/quic/blob/main/tests/runtest.sh)
