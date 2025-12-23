FROM alpine:latest

RUN apk add --no-cache \
    build-base \
    g++ \
    libmnl-dev \
    libnetfilter_queue-dev \
    linux-headers \
    iptables



WORKDIR /app
COPY Core.cpp .
COPY Core.hpp .
COPY entrypoint.sh .

RUN g++ -std=gnu++20 Core.cpp -o core -lmnl -lnetfilter_queue

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]