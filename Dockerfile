# taphttp container image, for running next to a consumer (e.g. spall) under
# docker compose. Lifted from spall's docker/taphttp/Dockerfile.
#
#   docker build -t taphttp .
#   docker run --rm -p 127.0.0.1:8080:8080 \
#     -v taphttp-ca:/ca -v taphttp-data:/data taphttp
#
# Publish the port on 127.0.0.1 only: the default command runs an open proxy
# (--allow-open-proxy), and binding 0.0.0.0 inside the container is safe only
# because of that.

FROM rust:1.90-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin taphttp \
 && install -m 0755 target/release/taphttp /usr/local/bin/taphttp

FROM debian:bookworm-slim
# ca-certificates: trust roots for upstream TLS.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 taphttp \
 && useradd --system --uid 10001 --gid taphttp --no-create-home taphttp \
 && mkdir -p /data /ca /token \
 && chown taphttp:taphttp /data /ca /token
COPY --from=build /usr/local/bin/taphttp /usr/local/bin/taphttp
USER taphttp
# The CA cert and key live in /ca, on their own volume. Never share it with
# the traffic log volume (/data): consumers mount that one.
ENV TAPHTTP_DATA=/ca
# When sqlite is on (--sqlite / --api-listen), keep the database beside the
# log rather than beside ca.key.
ENV TAPHTTP_DB=/data/traffic.db
# With --api-listen, the lever API token lives on its own volume (/token),
# which consumers mount read-only. It survives restarts and isn't printed.
ENV TAPHTTP_API_TOKEN_FILE=/token/api-token
VOLUME ["/ca", "/data", "/token"]
EXPOSE 8080
ENTRYPOINT ["taphttp"]
# --allow-open-proxy: the container listens on 0.0.0.0 so the published port
# works, and the README says to publish it on 127.0.0.1 only. For a remote
# deployment, replace the command and use --proxy-auth-file + --proxy-tls.
CMD ["start", "--listen", "0.0.0.0:8080", "--allow-open-proxy", "--log-file", "/data/traffic.jsonl"]
