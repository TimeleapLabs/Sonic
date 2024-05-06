#!/bin/sh
cd .. && make all && cd docker
cp -r ../build .
docker build --build-arg="UBUNTU_VERSION=latest" -t sonic:latest --no-cache .
rm -rf build
