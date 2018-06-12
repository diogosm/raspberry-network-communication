FROM ubuntu:xenial

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update

RUN apt-get -y install software-properties-common
RUN apt-get -y install git wget
RUN apt-get -y install python python3 libpython-dev python-dev libpython3-dev* python3-dev

RUN mkdir -p /kodo



