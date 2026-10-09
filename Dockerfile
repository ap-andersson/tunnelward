# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine3.24 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure Go (SQLite via modernc.org/sqlite), so no cgo and easy cross-builds.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/tunnelward ./cmd/tunnelward

FROM alpine:3.24.2
# nft applies the firewall ruleset. Everything else talks netlink directly.
RUN apk add --no-cache nftables
COPY --from=build /out/tunnelward /usr/local/bin/tunnelward
ENV TW_DATA_DIR=/data
VOLUME /data
EXPOSE 51820/udp 8080/tcp
ENTRYPOINT ["/usr/local/bin/tunnelward"]
