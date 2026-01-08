#!/bin/bash
set -e

# Substitute environment variables in the PowerDNS configuration template
envsubst < /etc/powerdns/pdns.d/gmysql.conf.template > /etc/powerdns/pdns.d/gmysql.conf

# Start PowerDNS server
exec /usr/sbin/pdns_server
