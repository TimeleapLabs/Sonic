ARG UBUNTU_VERSION
FROM ubuntu:${UBUNTU_VERSION}
LABEL maintainer="hi@kenshi.io"

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /app
COPY ./build/sonicd sonicd
COPY ./entrypoint.sh entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
