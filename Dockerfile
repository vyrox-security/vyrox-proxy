# A dependency in Cargo.lock requires the Rust 2024 edition (Rust >= 1.85),
# so the old rust:1.78 base failed to build. Track latest stable 1.x on
# bookworm so the produced binary is glibc-compatible with the runtime stage.
FROM rust:1-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/vyrox-proxy /usr/local/bin/vyrox-proxy
EXPOSE 3000
CMD ["/usr/local/bin/vyrox-proxy"]
