FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    xinetd \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create simple Python implementations of legacy services
COPY services.py /usr/local/bin/
RUN chmod +x /usr/local/bin/services.py

# Configure xinetd for UDP services
COPY xinetd.d/* /etc/xinetd.d/
RUN chmod 644 /etc/xinetd.d/*

# Create service user
RUN useradd -r -s /bin/false udpservices

EXPOSE 7/udp 9/udp 13/udp 17/udp 19/udp 37/udp

CMD ["/usr/sbin/xinetd", "-dontfork", "-stayalive"]