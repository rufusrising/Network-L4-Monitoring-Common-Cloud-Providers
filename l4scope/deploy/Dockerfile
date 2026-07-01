# Multi-stage build → tiny static image. Default build is std-only, so the
# builder needs no system libraries.
FROM rust:1.79-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p l4scope-agent

# Distroless static runtime. For the `live` backend, use a base that also has
# tcpdump/tshark (e.g. debian-slim + `apt-get install -y tcpdump`) and run with
# NET_ADMIN/NET_RAW. For eBPF, build with `--features ebpf` and add CAP_BPF.
FROM gcr.io/distroless/static-debian12
COPY --from=build /src/target/release/l4scope /usr/local/bin/l4scope
COPY config/l4scope.toml /etc/l4scope/l4scope.toml
EXPOSE 9560
# Default to the no-privilege demo; override the command for real capture.
ENTRYPOINT ["/usr/local/bin/l4scope"]
CMD ["--demo"]
