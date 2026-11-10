# The Pubky Switch service.
#
#   docker build -t pubky-switch .
#   docker run -e PUBKY_SWITCH_DATABASE_URL=postgres://... \
#     -v switch-keys:/var/lib/pubky-switch/keys pubky-switch
#
# See docs/configuration.md.

FROM rust:1.91.1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pubky-switch \
    && cp target/release/pubky-switch /pubky-switch \
    && mkdir -p /state/keys

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /pubky-switch /usr/local/bin/pubky-switch
COPY docker/config.toml /etc/pubky-switch/config.toml
# The key store. Mount a volume here that database backups don't cover.
COPY --from=build --chown=65532:65532 /state /var/lib/pubky-switch
VOLUME ["/var/lib/pubky-switch/keys"]
ENV PUBKY_SWITCH_CONFIG=/etc/pubky-switch/config.toml
# The API listener, once server.origin is set, and the operator listener: health and
# metrics.
EXPOSE 8080 9090
USER nonroot
ENTRYPOINT ["/usr/local/bin/pubky-switch"]
CMD ["run"]
