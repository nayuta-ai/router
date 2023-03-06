FROM ubuntu:20.04

LABEL maintainer "srz_zumix <https://github.com/srz-zumix>"

ARG BRANCH_OR_TAG=main
ARG CMAKE_OPTIONS=
ENV DEBIAN_FRONTEND=noninteractive
RUN env \
  && apt-get update \
  && apt-get install -q -y vim git cmake make g++ lcov \
      gettext-base jq curl net-tools\
      libbsd0 libbsd-dev sudo\
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 -b $BRANCH_OR_TAG -q https://github.com/google/googletest.git /googletest
RUN mkdir -p /googletest/build
WORKDIR /googletest/build
RUN cmake .. ${CMAKE_OPTIONS} && make && make install
WORKDIR /workspace
RUN rm -rf /googletest