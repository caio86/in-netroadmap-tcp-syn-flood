FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-scapy \
    procps \
    net-tools \
    iputils-ping \
    iproute2 \
    bash \
    curl \
    vlc \
    iperf3 \
    tcpdump \
    tcpreplay \
    ethtool \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/geteuid/getppid/' /usr/bin/vlc

COPY scripts /scripts

CMD /bin/bash
