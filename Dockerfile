FROM rust:1.78 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/vyrox-proxy /usr/local/bin/vyrox-proxy
EXPOSE 3000
CMD ["/usr/local/bin/vyrox-proxy"]
