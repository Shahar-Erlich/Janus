FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    libmnl-dev \
    libnetfilter-queue-dev \
    iproute2 \
    iptables \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN git clone --depth=1 https://github.com/seladb/PcapPlusPlus.git && \
    cd PcapPlusPlus && \
    mkdir build && cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

WORKDIR /app
COPY . .

RUN cmake -S . -B build && \
    cmake --build build

CMD ["sleep", "infinity"]
