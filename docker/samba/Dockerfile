FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    samba \
    && rm -rf /var/lib/apt/lists/*

# Configure Samba for NetBIOS
COPY smb.conf /etc/samba/smb.conf

EXPOSE 137/udp 138/udp 139/tcp 445/tcp

CMD ["nmbd", "-F", "-S", "--no-process-group"]