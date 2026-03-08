FROM debian:bullseye

RUN echo 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20220228T000000Z bullseye main' > /etc/apt/sources.list

RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y redis-server lua5.1 && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 6379

CMD ["redis-server", "--protected-mode", "no"]