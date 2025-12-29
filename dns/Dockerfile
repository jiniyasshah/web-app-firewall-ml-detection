FROM ubuntu:24.04

# Install PowerDNS and MySQL backend
RUN apt-get update && apt-get install -y \
    pdns-server \
    pdns-backend-mysql \
    && rm -rf /var/lib/apt/lists/*

# Remove default config
RUN rm -f /etc/powerdns/pdns.d/bind.conf

# Copy our custom config
COPY pdns.conf /etc/powerdns/pdns.d/gmysql.conf

EXPOSE 53/tcp
EXPOSE 53/udp

CMD ["/usr/sbin/pdns_server"]