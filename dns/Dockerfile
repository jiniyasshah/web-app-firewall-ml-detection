FROM ubuntu:24.04

# Install PowerDNS, MySQL backend, and gettext-base for envsubst
RUN apt-get update && apt-get install -y \
    pdns-server \
    pdns-backend-mysql \
    gettext-base \
    && rm -rf /var/lib/apt/lists/*

# Remove default config
RUN rm -f /etc/powerdns/pdns.d/bind.conf

# Copy template config and entrypoint script
COPY pdns.conf.template /etc/powerdns/pdns.d/gmysql.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/tcp
EXPOSE 53/udp

CMD ["/entrypoint.sh"]