FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update
RUN apt-get install -y git g++ make autoconf automake libtool pkg-config gnutls-dev

RUN git clone --recurse-submodules https://github.com/ngtcp2/nghttp3
RUN cd nghttp3 && autoreconf -i && ./configure --prefix=/usr/ && \
    make -j$(nproc) && make install && cd .. && rm -rf nghttp3

RUN git clone https://github.com/lxin/quic
RUN cd quic && ./autogen.sh && \
    ./configure --prefix=/usr --without-modules && make -j$(nproc) && make install && cd ..

COPY interop_test.c interop_test.c
RUN gcc interop_test.c -o interop_test -lnghttp3 -lquic -lgnutls && \
    rm -rf quic interop_test.c

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
