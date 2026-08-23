# ---- Build stage ----
FROM rust:1.81-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config && rm -rf /var/lib/apt/lists/*
COPY api/ ./api/
WORKDIR /app/api
RUN cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/api/target/release/secure-auth-api /usr/local/bin/secure-auth-api
COPY dashboard /dashboard
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://localhost:8080/health || exit 1
CMD ["secure-auth-api"]
