FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends redis-server=5:6.0.15-1 lua5.1 && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 6379

CMD ["redis-server", "--protected-mode", "no"]