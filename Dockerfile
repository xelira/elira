# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.97
FROM rust:${RUST_VERSION}-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake ninja-build perl pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release -p elira --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 elira \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/elira \
        --no-create-home --shell /usr/sbin/nologin elira \
    && install -d -o root -g root -m 0755 /etc/elira \
    && install -d -o elira -g elira -m 0755 /var/lib/elira

COPY --from=builder /src/target/release/elira /usr/local/bin/elira

EXPOSE 8080/tcp 8443/tcp 443/tcp 443/udp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["bash", "-c", "for port in 8080 8443 443; do (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && exit 0; done; exit 1"]

USER elira

ENTRYPOINT ["/usr/local/bin/elira", "run", "--config", "/etc/elira/elira.toml"]
