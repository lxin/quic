# QUIC in Linux Kernel

## Introduction

The QUIC protocol, defined in RFC 9000, is a secure, multiplexed transport built on top of UDP. It
enables low-latency connection establishment, stream-based communication with flow control, and
supports connection migration across network paths, while ensuring confidentiality, integrity, and
availability.

This implementation introduces QUIC support in Linux Kernel, offering several key advantages:

- **In-Kernel QUIC Support for Subsystems**: Enables kernel subsystems such as SMB and NFS to
operate over QUIC with minimal changes. Once the handshake is complete via the net/handshake APIs,
data exchange proceeds over standard in-kernel transport interfaces.

- **Standard Socket API Semantics**: Implements core socket operations (listen(), accept(),
connect(), sendmsg(), recvmsg(), close(), getsockopt(), setsockopt(), getsockname(), and
getpeername()), allowing user space to interact with QUIC sockets in a familiar, POSIX-compliant
way.

- **ALPN-Based Connection Dispatching**: Supports in-kernel ALPN (Application-Layer Protocol
Negotiation) routing, allowing demultiplexing of QUIC connections across different user-space
processes based on the ALPN identifiers.

- **Performance Enhancements**: Handles all control messages in-kernel to reduce syscall overhead,
incorporates zero-copy mechanisms such as sendfile() minimize data movement, and is also
structured to support future crypto hardware offloads.

## Implementation

### General Idea

The central design is to implement QUIC within the kernel while delegating the handshake to
userspace.

- **What's in Userspace**: Only the processing and creation of raw TLS Handshake Messages are
handled in userspace, facilitated by a TLS library like GnuTLS. These messages are exchanged
between kernel and userspace via sendmsg() and recvmsg(), with cryptographic details conveyed
through control messages (cmsg). See: [libquic/](https://github.com/lxin/quic/tree/main/libquic).

- **What's in Kernel**: The entire QUIC protocol, aside from the TLS Handshake Messages processing
and creation, is managed within the kernel. Rather than using a Upper Layer Protocol (ULP) layer,
this implementation establishes a socket of type IPPROTO_QUIC (similar to IPPROTO_MPTCP), operating
over UDP tunnels. See: [modules/net/quic/](https://github.com/lxin/quic/tree/main/modules/net/quic).

- **How Kernel Consumers Use It**: Kernel consumers can initiate a handshake request from the kernel
to userspace using the existing
[net/handshake netlink](https://docs.kernel.org/networking/tls-handshake.html). The userspace
component, such as tlshd service in [ktls-utils](https://github.com/oracle/ktls-utils), then manages
the processing of the QUIC handshake request.

### Infrastructures

- Handshake Architecture:

      +------+  +------+
      | APP1 |  | APP2 | ...
      +------+  +------+
      +------------------------------------------+
      |     {quic_client/server_handshake()}     |
      +------------------------------------------+       +-------------+
       {send/recvmsg()}      {set/getsockopt()}          |    tlshd    |
       [CMSG handshake_info] [SOCKOPT_CRYPTO_SECRET]     +-------------+
                             [SOCKOPT_TRANSPORT_PARAM_EXT]    |   ^
                    | ^                  | ^                  |   |
      Userspace     | |                  | |                  |   |
      --------------|-|------------------|-|------------------|---|-------
      Kernel        | |                  | |                  |   |
                    v |                  v |                  v   |
      +------------------+-----------------------+       +-------------+
      | protocol, timer, | socket (IPPROTO_QUIC) |<--+   | handshake   |
      |                  +-----------------------+   |   |netlink APIs |
      | common, family,  | outqueue  |  inqueue  |   |   +-------------+
      |                  +-----------------------+   |      |       |
      | stream, connid,  |         frame         |   |   +-----+ +-----+
      |                  +-----------------------+   |   |     | |     |
      | path, pnspace,   |         packet        |   |---| SMB | | NFS |...
      |                  +-----------------------+   |   |     | |     |
      | cong, crypto     |       UDP tunnels     |   |   +--+--+ +--+--+
      +------------------+-----------------------+   +------+-------|

- Application Data Architecture:

      +------+  +------+
      | APP1 |  | APP2 | ...
      +------+  +------+
       {send/recvmsg()}   {set/getsockopt()}              {recvmsg()}
       [CMSG stream_info] [SOCKOPT_KEY_UPDATE]            [EVENT conn update]
                          [SOCKOPT_CONNECTION_MIGRATION]  [EVENT stream update]
                          [SOCKOPT_STREAM_OPEN/RESET/STOP]
                    | ^               | ^                     ^
      Userspace     | |               | |                     |
      --------------|-|---------------|-|---------------------|-----------
      Kernel        | |               | |                     |
                    v |               v |  |------------------+
      +------------------+-----------------------+
      | protocol, timer, | socket (IPPROTO_QUIC) |<--+{kernel_send/recvmsg()}
      |                  +-----------------------+   |{kernel_set/getsockopt()}
      | common, family,  | outqueue  |  inqueue  |   |{kernel_recvmsg()}
      |                  +-----------------------+   |
      | stream, connid,  |         frame         |   |   +-----+ +-----+
      |                  +-----------------------+   |   |     | |     |
      | path, pnspace,   |         packet        |   |---| SMB | | NFS |...
      |                  +-----------------------+   |   |     | |     |
      | cong, crypto     |       UDP tunnels     |   |   +--+--+ +--+--+
      +------------------+-----------------------+   +------+-------|

### Features
This implementation offers fundamental support for the following RFCs:

- RFC9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC9001 - Using TLS to Secure QUIC
- RFC9002 - QUIC Loss Detection and Congestion Control
- RFC9221 - An Unreliable Datagram Extension to QUIC
- RFC9287 - Greasing the QUIC Bit
- RFC9368 - Compatible Version Negotiation for QUIC
- RFC9369 - QUIC Version 2

The socket APIs for QUIC follow the RFC draft:

- The Sockets API Extensions for In-kernel QUIC Implementations

### Next Step
- Submit QUIC module to upstream kernel.
- Submit quic_handshake() in libquic to gnutls library.
- Implement HW crypto offloading infrastructure.

## INSTALL

Both QUIC Kernel Module and Libquic will be built and installed simply by the commands below:

    Packages Required: (kernel_version >= 6.1)
    - make autoconf automake libtool pkg-config
    - gnutls-devel kernel-devel (yum)
      gnutls-dev linux-headers-$(uname -r) (apt-get)

    # cd /home/lxin (my home directory)
    # git clone https://github.com/lxin/quic.git
    # cd quic/
    # ./autogen.sh
    # ./configure --prefix=/usr
    # make
    # sudo make install
    # sudo make check (optional, run selftests)

NOTE: For these who want to integrate QUIC modules into kernel source code (e.g.
/home/lxin/net-next/), follow the instruction below to build and install kernel first, then the
commands above will skip QUIC modules building and use the one provided by kernel.

    # cp -r modules/include modules/net /home/lxin/net-next
    # cd /home/lxin/net-next/
    # sed -i 's@.*sctp.*@&\nobj-$(CONFIG_IP_QUIC)\t\t+= quic/@' net/Makefile
    # sed -i 's@.*sctp.*@&\nsource "net/quic/Kconfig"@' net/Kconfig

    Then build kernel with:

    CONFIG_IP_QUIC=m
    CONFIG_IP_QUIC_TEST=m

Also libquic is not necessary if you're able to use raw socket APIs and gnutls APIs to complete
the QUIC handshake, see
[Raw Socket APIs with more Control](https://github.com/lxin/quic#raw-socket-apis-with-more-control).

## USE CASES

### Kernel Consumers with ktls-utils:
    Packages Required:
    - keyutils
    - glib2-devel libnl3-devel keyutils-libs-devel (yum)
      libglib2.0-dev libnl-genl-3-dev libkeyutils-dev (apt-get)

    # cd /home/lxin
    # git clone https://github.com/oracle/ktls-utils
    # cd ktls-utils/
    # ./autogen.sh
    # ./configure --with-systemd --sysconfdir=/etc
    # make
    # sudo make install

    # sudo vim /etc/tlshd/config
      [debug]
      loglevel=0
      tls=0
      nl=0

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

    # sudo systemctl enable --now tlshd

    # cd /home/lxin/quic
    # sudo make check tests=tlshd (optional, run some tests for tlshd)

After tlshd service is started, Kernel Consumers can use these user APIs from kernel space,
see [Use in Kernel Space](https://github.com/lxin/quic/#use-in-kernel-space).

### HTTP/3 Client with Curl:
    # cd /home/lxin
    # git clone --recurse-submodules https://github.com/ngtcp2/nghttp3.git
    # cd nghttp3
    # autoreconf -i
    # ./configure --prefix=/usr/
    # make
    # sudo make install

    # cd /home/lxin/quic
    # sudo make check tests=http3 (optional, run some tests for http3)

Moritz Buhl has made curl http3 work over linuxquic:

    # git clone https://github.com/moritzbuhl/curl.git -b linux_curl
    # cd curl
    # autoreconf -i
    # ./configure --prefix=/usr/ --with-gnutls --with-linux-quic --with-nghttp3
    # make -j$(nproc)
    # sudo make install

The test can be done with curl:

    # curl --http3-only --ipv4 https://cloudflare-quic.com/
    # curl --http3-only --ipv4 https://facebook.com/
    # curl --http3-only --ipv4 https://litespeedtech.com/
    # curl --http3-only --ipv4 https://nghttp2.org:4433/
    # curl --http3-only --ipv4 https://outlook.office.com/
    # curl --http3-only --ipv4 https://www.google.com/

### QUIC Interop Test with quic-interop-runner:
    Packages Required:
    - cmake flex bison byacc ninja-build
    - python3-pip docker docker-compose
    - libgcrypt-devel c-ares-devel glib2-devel libpcap-devel (yum)
      libgcrypt20-dev libc-ares-dev libglib2.0-dev libpcap-dev (apt-get)

    Build latest wireshark:
    # cd /home/lxin
    # git clone https://github.com/wireshark/wireshark.git
    # cd wireshark/
    # cmake -GNinja -DBUILD_wireshark=0 -DBUILD_qtshark=0 -DBUILD_editcap=1 \
      -DBUILD_capinfos=0 -DBUILD_text2pcap=0 -DBUILD_rawshark=0 -DBUILD_sdjournal=0 \
      -DBUILD_sshdump=0 -DBUILD_ciscodump=0 -DBUILD_sharkd=0 -DENABLE_STATIC=1 \
      -DENABLE_PLUGINS=0 -DENABLE_LIBXML2=0 -DENABLE_BROTLI=0 -DENABLE_GNUTLS=1 .
    # ninja
    # sudo ninja install

    Build test image (Optional):
    # cd /home/lxin
    # git clone https://github.com/quic-interop/quic-network-simulator.git
    # cd quic-network-simulator/
    # cp -r /home/lxin/quic/tests/interop linuxquic-interop
    # CLIENT="linuxquic-interop" SERVER="linuxquic-interop" docker compose build
    # docker image ls linuxquic-interop
      REPOSITORY           TAG       IMAGE ID       CREATED          SIZE
      linuxquic-interop    latest    3329ae030c62   52 seconds ago   568MB

    Run tests:
    # cd /home/lxin
    # git clone https://github.com/quic-interop/quic-interop-runner.git
    # cd quic-interop-runner/
    # pip3 install -r requirements.txt

You can change implementations.json file to run test cases between different implementations. Here
displays the testing result between linuxquic ngtcp2 quiche and msquic:

    # cat implementations.json
      {
        "linuxquic": {
          "image": "quay.io/lxin/linuxquic-interop:latest",
          "url": "https://github.com/lxin/quic",
          "role": "both"
        },
        "ngtcp2": {
          "image": "ghcr.io/ngtcp2/ngtcp2-interop:latest",
          "url": "https://github.com/ngtcp2/ngtcp2",
          "role": "both"
        },
        "quiche": {
          "image": "cloudflare/quiche-qns:latest",
          "url": "https://github.com/cloudflare/quiche",
          "role": "both"
        },
        "msquic": {
          "image": "ghcr.io/microsoft/msquic/qns:main",
          "url": "https://github.com/microsoft/msquic",
          "role": "both"
        }
      }

    # python3 run.py
      ...
      Run took 7:03:10.119649

      Tests:
      +-----------+---------------------------------------------+----------------------------------------------+
      |           |                     linuxquic               |                       ngtcp2                 |
      +-----------+---------------------------------------------+----------------------------------------------+
      | linuxquic | ✓(H,DC,LR,C20,M,S,R,Z,3,B,U,E,A,L1,L2,C1,C2,| ✓(H,DC,LR,C20,M,S,R,Z,3,B,U,E,A,L1,L2,C1,C2, |
      |           |   6,V2)                                     |   6,V2)                                      |
      |           |                      ?()                    |                      ?()                     |
      |           |                      ✕()                    |                      ✕()                     |
      +-----------+---------------------------------------------+----------------------------------------------+
      |   ngtcp2  | ✓(H,DC,LR,C20,M,S,R,Z,3,B,U,E,A,L1,L2,C1,C2,| ✓(H,DC,LR,C20,M,S,R,Z,3,B,U,E,A,L1,L2,C1,C2, |
      |           |   6,V2)                                     |   6,V2)                                      |
      |           |                      ?()                    |                      ?()                     |
      |           |                      ✕()                    |                      ✕()                     |
      +-----------+---------------------------------------------+----------------------------------------------+
      |   quiche  |    ✓(H,DC,LR,M,S,R,Z,3,B,A,L1,L2,C1,C2,6)   |   ✓(H,DC,LR,M,S,R,Z,3,B,A,L1,L2,C1,C2,6)     |
      |           |                 ?(C20,U,E,V2)               |                 ?(C20,U,E,V2)                |
      |           |                      ✕()                    |                      ✕()                     |
      +-----------+---------------------------------------------+----------------------------------------------+
      |   msquic  |    ✓(H,DC,LR,C20,M,S,R,B,U,A,L1,L2,C1,C2,6, |   ✓(H,DC,LR,C20,M,S,R,B,U,A,L1,L2,C1,C2,6)   |
      |           |                    ?(Z,3,E)                 |                    ?(Z,3,E)                  |
      |           |                      ✕()                    |                     ✕(V2)                    |
      +-----------+---------------------------------------------+----------------------------------------------+
      +-----------+---------------------------------------------+----------------------------------------------+
      |           |                    quiche                   |                     msquic                   |
      +-----------+---------------------------------------------+----------------------------------------------+
      | linuxquic | ✓(H,DC,LR,C20,M,S,R,Z,3,B,U,A,L1,L2,C1,C2,6)| ✓(H,DC,LR,C20,M,S,R,Z,B,U,A,L1,L2,C1,C2,6,V2)|
      |           |                   ?(E,V2)                   |                     ?(3,E)                   |
      |           |                     ✕()                     |                      ✕()                     |
      +-----------+---------------------------------------------+----------------------------------------------+
      |   ngtcp2  | ✓(H,DC,LR,C20,M,S,R,Z,3,B,U,A,L1,L2,C1,C2,6)|  ✓(H,DC,LR,C20,M,S,R,Z,B,U,L1,L2,C1,C2,6,V2) |
      |           |                   ?(E,V2)                   |                    ?(3,E,A)                  |
      |           |                     ✕()                     |                      ✕()                     |
      +-----------+---------------------------------------------+----------------------------------------------+
      |   quiche  |     ✓(H,DC,LR,M,S,R,Z,3,B,A,L1,L2,C2,6)     |          ✓(H,DC,LR,M,S,R,Z,B,L2,C2,6)        |
      |           |                ?(C20,U,E,V2)                |                ?(C20,3,U,E,V2)               |
      |           |                    ✕(C1)                    |                   ✕(A,L1,C1)                 |
      +-----------+---------------------------------------------+----------------------------------------------+
      |   msquic  |    ✓(H,DC,LR,C20,M,S,R,B,A,L1,L2,C1,C2,6)   |   ✓(H,DC,LR,C20,M,S,R,B,U,L1,L2,C1,C2,6,V2)  |
      |           |                 ?(Z,3,E,V2)                 |                   ?(Z,3,E,A)                 |
      |           |                     ✕(U)                    |                      ✕()                     |
      +-----------+---------------------------------------------+----------------------------------------------+

      Measurments:
      +-----------+----------------------+-----------------------+----------------------+----------------------+
      |           |      linuxquic       |         ngtcp2        |        quiche        |        msquic        |
      +-----------+----------------------+-----------------------+----------------------+----------------------+
      | linuxquic | G: 8671 (± 273) kbps |  G: 5824 (± 552) kbps | G: 9097 (± 34) kbps  | G: 7393 (± 406) kbps |
      |           | C: 3731 (± 168) kbps |  C: 2951 (± 261) kbps | C: 6841 (± 191) kbps | C: 9016 (± 95) kbps  |
      +-----------+----------------------+-----------------------+----------------------+----------------------+
      |   ngtcp2  | G: 9104 (± 141) kbps |  G: 9028 (± 273) kbps | G: 9305 (± 12) kbps  | G: 8971 (± 15) kbps  |
      |           | C: 3704 (± 194) kbps | C: 6852 (± 1811) kbps | C: 7512 (± 306) kbps | C: 7976 (± 412) kbps |
      +-----------+----------------------+-----------------------+----------------------+----------------------+
      |   quiche  | G: 9137 (± 149) kbps |  G: 9146 (± 12) kbps  | G: 9155 (± 28) kbps  | G: 7601 (± 416) kbps |
      |           | C: 4877 (± 165) kbps | C: 7813 (± 2508) kbps | C: 7649 (± 89) kbps  | C: 7422 (± 107) kbps |
      +-----------+----------------------+-----------------------+----------------------+----------------------+
      |   msquic  | G: 8929 (± 212) kbps |  G: 7182 (± 873) kbps | G: 9401 (± 11) kbps  |  G: 9091 (± 4) kbps  |
      |           |          C           |           C           | C: 6989 (± 292) kbps | C: 7089 (± 506) kbps |
      +-----------+----------------------+-----------------------+----------------------+----------------------+

### Performance Test with iperf:
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

QUIC (disable_1rtt_encryption) vs TCP iperf testing over 100G physical NIC with different packet
size and MTU:

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

Note kTLS testing is using iperf from https://github.com/Mellanox/iperf_ssl, and the only way to
disable TCP GSO is to remove sk_is_tcp() check in sk_setup_caps() and bring sk_can_gso() back in
kernel code.

As the test data shows, the TCP GSO contributes to performance a lot for TCP and kTLS with mtu 1500
and large msgs. With TCP GSO disabled, the small performance gap between QUIC and kTLS, QUIC with
disable_1rtt_encryption and TCP is caused by:

- QUIC has an extra copy on TX path.
- QUIC has an extra encryption for header protection.
- QUIC has a longer header for the stream DATA.

### QUIC Test with NetPerfMeter

[Network Performance Meter&nbsp;(NetPerfMeter)](https://www.nntb.no/~dreibh/netperfmeter/) is a
network performance metering tool for the TCP, MPTCP, SCTP, UDP, DCCP, and QUIC transport protocols.
Particularly, it can be utilized to compare concurrent flows of different protocols to e.g.&nbsp;
evaluate congestion control behavior using saturated and non-saturated flows, with various
configuration options.

NetPerfMeter can be built with support for Linux Kernel QUIC (details in
[NetPerfMeter QUIC Communication](https://www.nntb.no/~dreibh/netperfmeter/#quic-communication)),
to run performance evaluations:

* Server side using base port 9000:

  ```bash
  netperfmeter 9000 \
     --control-over-tcp \
     --tls-key  server.domain.example.key \
     --tls-cert server.domain.example.crt \
     --tls-ca   ca.crt \
  ```

* Client side establishing a bidirectional, saturated QUIC flow using messages of 1000&nbsp;bytes:

  ```bash
   netperfmeter $SERVER_IP:9000 \
      --control-over-tcp \
      --tls-hostname server.domain.example \
      --tls-ca $DIRECTORY/TestCA/TestLevel1/certs/TestLevel1.crt \
      --quic const0:const1000:const0:const1000
  ```

  `SERVER_IP` contains the server's IP address.

Wireshark in its latest version supports the dissection of NetPerfMeter payload traffic over QUIC
for analysis; see [NetPerfMeter Wireshark](https://www.nntb.no/~dreibh/netperfmeter/#wireshark)
for the configuration details.

## USER APIS

Similar to TCP and SCTP, a typical server and client use the following system call sequence to
communicate:

      Client                             Server
    ----------------------------------------------------------------------
    sockfd = socket(IPPROTO_QUIC)      listenfd = socket(IPPROTO_QUIC)
    bind(sockfd)                       bind(listenfd)
                                       listen(listenfd)
    connect(sockfd)
    quic_client_handshake(sockfd)
                                       sockfd = accept(listenfd)
                                       quic_server_handshake(sockfd, cert)

    sendmsg(sockfd)                    recvmsg(sockfd)
    close(sockfd)                      close(sockfd)
                                       close(listenfd)

This section shows you the basic usage of QUIC, you can get more details via man page:

    # man quic

### Basic APIs Use in User Space

- these APIs are provided (see [tests/sample_test.c](https://github.com/lxin/quic/blob/main/tests/sample_test.c) for how APIs are used):

      int quic_client_handshake(int sockfd, const char *pkey_file,
                                const char *hostname, const char *alpns);
      int quic_server_handshake(int sockfd, const char *pkey_file,
                                const char *cert_file, const char *alpns);

      ssize_t quic_sendmsg(int sockfd, const void *msg, size_t len,
                           int64_t sid, uint32_t flags);
      ssize_t quic_recvmsg(int sockfd, void *msg, size_t len,
                           int64_t *sid, uint32_t *flags);

- include the header file in c file like sample_test.c:

      #include <netinet/quic.h>

- then build it by:

      # gcc sample_test.c -o sample_test -lquic

### Advanced APIs with more TLS Handshake Parameters

- these APIs are provided (see [tests/ticket_test.c](https://github.com/lxin/quic/blob/main/tests/ticket_test.c) for how APIs are used):

      int quic_handshake_init(gnutls_session_t session, struct quic_handshake_step **pstep);
      int quic_handshake_step(gnutls_session_t session, struct quic_handshake_step **pstep);
      void quic_handshake_deinit(gnutls_session_t session);

      int quic_handshake(gnutls_session_t session);

      int quic_session_get_data(gnutls_session_t session,
                                void *data, size_t *size);
      int quic_session_set_data(gnutls_session_t session,
                                const void *data, size_t size);

      int quic_session_get_alpn(gnutls_session_t session,
                                void *data, size_t *size);
      int quic_session_set_alpn(gnutls_session_t session,
                                const void *data, size_t size);

- include the header file in c file like ticket_test.c:

      #include <netinet/quic.h>

- then build it by:

      # gcc ticket_test.c -o ticket_test -lquic -lgnutls

### Raw Socket APIs with more Control

quic_client/server_handshake() and quic_handshake() in libquic are implemented with gnutls APIs and
socket APIs such as send/recvmsg() and set/getsocket().

For these who want more control or flexibility in the handshake, instead of using the APIs from
libquic, they should use the raw socket APIs and gnutls APIs to implement their own QUIC handshake
functions, and they may copy and reuse some code from libquic.

### Use in Kernel Space

NOTE: tlshd service must be installed and started, see
[Kernel Consumers with ktls-utils](https://github.com/lxin/quic#kernel-consumers-with-ktls-utils),
as it receives and handles the kernel handshake request for kernel sockets.

In kernel space, the use is pretty much like TCP sockets, except a extra handshake up-call.
(See [modules/net/quic/test/sample_test.c](https://github.com/lxin/quic/blob/main/modules/net/quic/test/sample_test.c) for examples)

      Client                             Server
    -------------------------------------------------------------------------
    __sock_create(IPPROTO_QUIC, &sock)  __sock_create(IPPROTO_QUIC, &sock)
    kernel_bind(sock)                   kernel_bind(sock)
                                        kernel_listen(sock)
    kernel_connect(sock)
    tls_client_hello_x509(args:{sock})
                                        kernel_accept(sock, &newsock)
                                        tls_server_hello_x509(args:{newsock})

    kernel_sendmsg(sock)                kernel_recvmsg(newsock)
    sock_release(sock)                  sock_release(newsock)
                                        sock_release(sock)

You can run the kernel test code as it shows in tlshd_tests() of
[tests/runtest.sh](https://github.com/lxin/quic/blob/main/tests/runtest.sh)

## Contributing

We welcome contributions from the community.

- **Mailing List**: The Linux QUIC developer mailing list is available at
[lists.linux.dev](https://subspace.kernel.org/lists.linux.dev.html).
You can subscribe to <quic@lists.linux.dev> or browse archived threads.

- **Reporting Features or Issues**: Bugs, feature requests, or socket API RFC discussions can be
submitted via the mailing list or GitHub issues.

- **Submitting Patches**: Patches can be sent through the mailing list or via GitHub pull requests.
