FROM golang:bullseye

RUN apt update && apt install -y libnetfilter-queue-dev

