FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    snmpd \
    snmp \
    && rm -rf /var/lib/apt/lists/*

# Configure SNMPD
COPY snmpd.conf /etc/snmp/snmpd.conf

EXPOSE 161/udp 162/udp

CMD ["snmpd", "-f", "-Lo", "-c", "/etc/snmp/snmpd.conf"]