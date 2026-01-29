FROM alpine:latest

RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    libpcap-dev \
    libmnl-dev \
    libnetfilter_queue-dev \
    iproute2 \
    iptables \
    netcat-openbsd \
    linux-headers \
    bash

WORKDIR /tmp

RUN git clone --depth=1 https://github.com/seladb/PcapPlusPlus.git && \
    cd PcapPlusPlus && \
    mkdir build && cd build && \
    cmake .. && \
    make -j$(getconf _NPROCESSORS_ONLN) && \
    make install


WORKDIR /app
COPY . .

RUN cmake -S . -B build && \
    cmake --build build

CMD ["sleep", "infinity"]
