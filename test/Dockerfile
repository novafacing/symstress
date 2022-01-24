FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Indiana/Indianapolis

RUN cp /etc/apt/sources.list /tmp/sources && \
    sed -i 's/^deb /deb-src /' /tmp/sources && \
    cat /tmp/sources >> /etc/apt/sources.list

RUN apt update -y && \
    apt install -y \
    git \
    build-essential \
    unzip && \
    apt build-dep -y coreutils

RUN apt install -y \
    rsync \
    wget

RUN git clone https://github.com/coreutils/coreutils.git coreutils

WORKDIR /coreutils

RUN ./bootstrap
RUn ./configure --help
