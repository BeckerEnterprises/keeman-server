# KeeMan API server as a container image.
#   podman build -t keeman-server .        (or: docker build -t keeman-server .)
# Volumes: /etc/keeman (config.toml, server_secret), /var/lib/keeman (data),
# /var/backups/keeman (backups). See README, "Containers".

FROM docker.io/library/rust:1.99.1-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 keeman \
 && useradd --system --uid 10001 --gid keeman --home-dir /nonexistent --shell /usr/sbin/nologin keeman \
 && install -d -o keeman -g keeman -m 0700 /etc/keeman /var/lib/keeman /var/backups/keeman
COPY --from=build /src/target/release/keeman-server /usr/local/bin/keeman-server
USER keeman
VOLUME ["/etc/keeman", "/var/lib/keeman", "/var/backups/keeman"]
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/keeman-server"]
CMD ["serve", "--config", "/etc/keeman/config.toml"]
