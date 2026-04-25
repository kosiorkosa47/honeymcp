# syntax=docker/dockerfile:1
FROM rust:1.95-slim-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
# build.rs reads .git/HEAD if present to stamp HONEYMCP_GIT_SHA. The build
# context here usually has no .git tree, so the script falls back to "unknown"
# at compile time. Release builds populate it via CI env (see release.yml).
RUN cargo build --release --locked

FROM debian:bookworm-slim
# curl is for the HEALTHCHECK script; ca-certificates + libssl3 are deps for
# outbound HTTPS if a future transport needs it; sqlite3 is a convenience for
# `docker exec` inspection. Everything else is stripped.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 sqlite3 curl \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /usr/sbin/nologin honeymcp \
 && mkdir -p /var/lib/honeymcp /opt/honeymcp/personas \
 && chown honeymcp:honeymcp /var/lib/honeymcp

COPY --from=builder /build/target/release/honeymcp /usr/local/bin/honeymcp
COPY personas /opt/honeymcp/personas

# Tiny healthcheck wrapper. Kept as its own script (not an inline HEALTHCHECK
# command) so compose override and bare `docker run` both pick it up without
# the caller having to spell out the curl invocation.
RUN printf '%s\n' '#!/bin/sh' 'exec curl -fsS --max-time 3 http://127.0.0.1:8080/healthz' \
        > /usr/local/bin/healthz \
 && chmod +x /usr/local/bin/healthz

USER honeymcp
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD ["/usr/local/bin/healthz"]

ENTRYPOINT ["/usr/local/bin/honeymcp"]
CMD ["--transport","http","--http-addr","0.0.0.0:8080","--persona","/opt/honeymcp/personas/github-admin.yaml","--db","/var/lib/honeymcp/hive.db","--jsonl","/var/lib/honeymcp/hive.jsonl"]
