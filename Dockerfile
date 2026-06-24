# syntax=docker/dockerfile:1
FROM rust:1.89-slim-bookworm AS builder
WORKDIR /build
ARG HONEYMCP_GIT_SHA=unknown
ARG HONEYMCP_BUILD_UNIX_TS
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
# Cargo parses [[bench]] entries from the manifest even when --bin scopes the
# build to the production binary; the file targets must exist on disk or the
# manifest fails to load. Cheap to copy (3 files, <500 lines) and it keeps the
# release binary scope tight via --bin honeymcp.
COPY benches ./benches
# build.rs reads HONEYMCP_GIT_SHA first, then falls back to .git/HEAD if the
# build context includes a git tree. Box deploys pass the origin/main commit as
# a build arg so /version always exposes the exact deployed revision.
RUN HONEYMCP_GIT_SHA="$HONEYMCP_GIT_SHA" \
    HONEYMCP_BUILD_UNIX_TS="$HONEYMCP_BUILD_UNIX_TS" \
    cargo build --bin honeymcp --release --locked

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

# Run from the persona/canary root so the binary auto-discovers a
# `./canaries.yaml` mounted at /opt/honeymcp/canaries.yaml (gitignored real
# Thinkst tokens). Absent or unparsable → placeholders render as realistic
# fakes; the container still boots.
WORKDIR /opt/honeymcp

USER honeymcp
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD ["/usr/local/bin/healthz"]

ENTRYPOINT ["/usr/local/bin/honeymcp"]
CMD ["--transport","http","--http-addr","0.0.0.0:8080", \
     "--persona","aws=/opt/honeymcp/personas/aws-admin.yaml", \
     "--persona","github=/opt/honeymcp/personas/github-admin.yaml", \
     "--persona","vercel=/opt/honeymcp/personas/vercel-admin.yaml", \
     "--persona","stripe=/opt/honeymcp/personas/stripe-finance.yaml", \
     "--default-persona","aws", \
     "--db","/var/lib/honeymcp/hive.db","--jsonl","/var/lib/honeymcp/hive.jsonl"]
