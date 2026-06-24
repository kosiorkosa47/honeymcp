#!/bin/sh
set -eu

# DOCKER-USER only sees Docker-forwarded packets, so this blocks container
# access to cloud metadata without affecting host-level IMDS access.
/sbin/iptables -C DOCKER-USER -d 169.254.169.254/32 -j DROP 2>/dev/null \
  || /sbin/iptables -I DOCKER-USER 1 -d 169.254.169.254/32 -j DROP
