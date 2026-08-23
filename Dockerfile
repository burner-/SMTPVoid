FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --home /data --shell /usr/sbin/nologin smtpvoid \
    && mkdir /data && chown smtpvoid:smtpvoid /data
COPY --from=build /src/target/release/smtpvoid /usr/local/bin/smtpvoid
USER smtpvoid
ENV SMTPVOID_DATA_DIR=/data
VOLUME /data
# 8080 web UI, 2525 SMTP, 4650 SMTPS by default; 80 is the ACME HTTP-01
# challenge and 443 the optional HTTPS UI, both configured in the admin UI.
EXPOSE 8080 2525 4650 80 443
ENTRYPOINT ["/usr/local/bin/smtpvoid"]
