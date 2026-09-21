# Optional disposable Linux environment for development on macOS/Linux.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bash ca-certificates curl jq openssl python3 iproute2 util-linux coreutils \
    docker.io docker-compose-v2 shellcheck \
    && rm -rf /var/lib/apt/lists/*
ENV LANG=C.UTF-8
WORKDIR /work
