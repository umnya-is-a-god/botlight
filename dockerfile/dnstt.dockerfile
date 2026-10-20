ARG image
FROM golang:alpine AS go
# a fixed release; the Go checksum database (sum.golang.org) verifies the
# module and all its dependencies during the download
ARG dnstt_version=v1.20260501.0
RUN CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" \
    www.bamsoftware.com/git/dnstt.git/dnstt-server@$dnstt_version
FROM $image
COPY --from=go /go/bin/dnstt-server /usr/local/bin/
# vpnbot: the shared tunnel account; a fixed uid for the iptables owner
# rules in start_dnstt.sh
RUN apk add --no-cache openssh iptables \
    && mkdir -p /root/.ssh \
    && adduser -D -u 10001 -s /bin/sh vpnbot
ENV ENV="/root/.ashrc"
