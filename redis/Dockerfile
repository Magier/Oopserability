FROM debian:buster

RUN apt-get update && \
    apt-get install -y redis-server=5:5.0.7-2 lua5.1 && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 6379

CMD ["redis-server", "--protected-mode", "no"]