FROM golang:1.21-bullseye as builder

WORKDIR /src/clickhouse-exporter

ARG CHOP_VERSION=release-0.20.1
ARG PROMU_VERSION=0.15.0

COPY . .

RUN git clone --single-branch --branch $CHOP_VERSION https://github.com/altinity/clickhouse-operator ../clickhouse-operator \
    && go install -v github.com/prometheus/promu@v$PROMU_VERSION \
    && /go/bin/promu build -v --prefix build


FROM debian:bullseye-slim
LABEL maintainer="Vasily Maryutenkov <vasily.maryutenkov@flant.com>"

COPY --from=builder /src/clickhouse-exporter/build/clickhouse-exporter /clickhouse-exporter

EXPOSE 8888/tcp

CMD [ "/clickhouse-exporter" ]
