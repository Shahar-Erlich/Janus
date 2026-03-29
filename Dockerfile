FROM alpine:latest

RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    curl \
    autoconf \
    automake \
    libtool \
    zlib-dev \
    abseil-cpp-dev \
    libpcap-dev \
    libmnl-dev \
    libnetfilter_queue-dev \
    re2-dev \
    iproute2 \
    iptables \
    netcat-openbsd \
    linux-headers \
    bash \
    python3

WORKDIR /tmp

# Install Protobuf C++ runtime + protoc matching generated files
RUN git clone --branch v33.1 --depth=1 https://github.com/protocolbuffers/protobuf.git && \
    cd protobuf && \
    git submodule update --init --recursive && \
    cmake -S . -B build \
      -Dprotobuf_BUILD_TESTS=OFF \
      -Dprotobuf_ABSL_PROVIDER=package \
      -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j$(getconf _NPROCESSORS_ONLN) && \
    cmake --install build

# Build PcapPlusPlus
RUN git clone --depth=1 https://github.com/seladb/PcapPlusPlus.git && \
    cd PcapPlusPlus && \
    mkdir build && cd build && \
    cmake .. && \
    make -j$(getconf _NPROCESSORS_ONLN) && \
    make install

WORKDIR /app
COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j$(getconf _NPROCESSORS_ONLN)

CMD ["sleep", "infinity"]