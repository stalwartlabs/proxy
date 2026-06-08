FROM --platform=$BUILDPLATFORM docker.io/lukemathwalker/cargo-chef:latest-rust-slim-trixie AS chef
WORKDIR /build

FROM --platform=$BUILDPLATFORM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path /recipe.json

FROM --platform=$BUILDPLATFORM chef AS builder
ARG TARGETPLATFORM
RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") echo "aarch64-unknown-linux-gnu" > /target.txt && echo "-C linker=aarch64-linux-gnu-gcc" > /flags.txt ;; \
    "linux/amd64") echo "x86_64-unknown-linux-gnu" > /target.txt && echo "-C linker=x86_64-linux-gnu-gcc" > /flags.txt ;; \
    *) exit 1 ;; \
    esac
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq --no-install-recommends build-essential cmake libclang-19-dev \
    g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    g++-x86-64-linux-gnu binutils-x86-64-linux-gnu
RUN rustup target add "$(cat /target.txt)"
COPY --from=planner /recipe.json /recipe.json
RUN RUSTFLAGS="$(cat /flags.txt)" cargo chef cook --target "$(cat /target.txt)" --release -p proxy --recipe-path /recipe.json
COPY . .
RUN RUSTFLAGS="$(cat /flags.txt)" cargo build --target "$(cat /target.txt)" --release -p proxy
RUN mv "/build/target/$(cat /target.txt)/release" "/output"

FROM docker.io/debian:trixie-slim
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq --no-install-recommends ca-certificates curl libcap2-bin && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r -g 2000 stalwart-proxy && \
    useradd -r -u 2000 -g 2000 -s /usr/sbin/nologin -M stalwart-proxy && \
    mkdir -p /etc/proxy && \
    chown stalwart-proxy:stalwart-proxy /etc/proxy
COPY --from=builder --chmod=0755 /output/proxy /usr/local/bin/proxy
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/proxy
USER stalwart-proxy
WORKDIR /etc/proxy
VOLUME ["/etc/proxy"]
EXPOSE	24 25 110 143 465 587 993 995 4190 443 9443
ENV PROXY_HEALTHCHECK_URL=https://127.0.0.1:9443/healthz
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsSk "$PROXY_HEALTHCHECK_URL" || exit 1
ENTRYPOINT ["/usr/local/bin/proxy"]
CMD ["/etc/proxy/config.toml"]
