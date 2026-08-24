FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
RUN cargo build --release

FROM debian:bookworm-slim
# ca-certificates: the ACME client verifies the CA's own HTTPS chain against the
# system trust store. libcap2-bin: only needed to run setcap below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /data --shell /usr/sbin/nologin smtpvoid \
    && mkdir /data && chown smtpvoid:smtpvoid /data
COPY --from=build /src/target/release/smtpvoid /usr/local/bin/smtpvoid
# The default submission ports (587/465) and the ACME/HTTPS ports (80/443) are
# privileged, and this image runs unprivileged. A file capability lets the
# binary bind them without running as root; Docker's default bounding set
# already permits CAP_NET_BIND_SERVICE.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/smtpvoid
USER smtpvoid
ENV SMTPVOID_DATA_DIR=/data
VOLUME /data
# 8080 web UI, 587 submission, 465 SMTPS by default; 80 is the ACME HTTP-01
# challenge and 443 the optional HTTPS UI, both configured in the admin UI.
EXPOSE 8080 587 465 80 443
ENTRYPOINT ["/usr/local/bin/smtpvoid"]
