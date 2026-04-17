# syntax=docker/dockerfile:1
FROM rust:1.88-slim-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 sqlite3 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin honeymcp
COPY --from=builder /build/target/release/honeymcp /usr/local/bin/honeymcp
COPY personas /opt/honeymcp/personas
RUN mkdir -p /var/lib/honeymcp && chown honeymcp:honeymcp /var/lib/honeymcp
USER honeymcp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/honeymcp"]
CMD ["--transport","http","--http-addr","0.0.0.0:8080","--persona","/opt/honeymcp/personas/github-admin.yaml","--db","/var/lib/honeymcp/hive.db","--jsonl","/var/lib/honeymcp/hive.jsonl"]
