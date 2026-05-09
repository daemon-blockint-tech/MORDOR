FROM ubuntu:24.04

LABEL org.mordor.component="sandbox"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    curl \
    wget \
    net-tools \
    tcpdump \
    strace \
    gdb \
    ltrace \
    binutils \
    xxd \
    jq \
    iproute2 \
    dnsutils \
    procps \
    vim-tiny \
    iptables \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash analyst

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
