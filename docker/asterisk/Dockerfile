FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    asterisk \
    && rm -rf /var/lib/apt/lists/*

# Basic SIP configuration
COPY sip.conf /etc/asterisk/sip.conf
COPY extensions.conf /etc/asterisk/extensions.conf

EXPOSE 5060/udp 5060/tcp

CMD ["asterisk", "-f", "-c"]