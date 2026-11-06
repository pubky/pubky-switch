# The Pubky Switch service.
#
#   docker build -t pubky-switch .
#   docker run -v ./config.toml:/etc/pubky-switch/config.toml pubky-switch
#
# See docs/configuration.md.

FROM rust:1.91.1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pubky-switch \
    && cp target/release/pubky-switch /pubky-switch

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /pubky-switch /usr/local/bin/pubky-switch
COPY docker/config.toml /etc/pubky-switch/config.toml
ENV PUBKY_SWITCH_CONFIG=/etc/pubky-switch/config.toml
# The operator listener: health and metrics.
EXPOSE 9090
USER nonroot
ENTRYPOINT ["/usr/local/bin/pubky-switch"]
CMD ["run"]
