ARG image
FROM $image
# microsocks is built from a fixed commit, wgcf is pinned by SHA-256
ARG microsocks_commit=307950cb1296b521fe86384fd695062ade5304b5
ARG wgcf_version=2.2.22
ARG wgcf_sha256=268d187e649870b603ad2e5c1b74a696251f6c2f6f075c726a174a0039b0b1e2
# security updates of the base image's packages (ca-certificates, openssl, ...)
# on every build, not only what the base image was pulled with
RUN apk upgrade --no-cache \
    && apk add --no-cache --virtual .build-deps alpine-sdk git \
    && apk add --no-cache iproute2 iptables openssh wireguard-tools jq bash \
    && git init -q /tmp/microsocks \
    && git -C /tmp/microsocks fetch -q --depth 1 https://github.com/rofl0r/microsocks $microsocks_commit \
    && git -C /tmp/microsocks checkout -q FETCH_HEAD \
    && [ "$(git -C /tmp/microsocks rev-parse HEAD)" = "$microsocks_commit" ] \
    && make -C /tmp/microsocks \
    && mv /tmp/microsocks/microsocks /usr/bin/microsocks \
    && rm -rf /tmp/microsocks \
    && apk del .build-deps \
    && mkdir /root/.ssh \
    && wget -O /usr/bin/wgcf https://github.com/ViRb3/wgcf/releases/download/v$wgcf_version/wgcf_${wgcf_version}_linux_amd64 \
    && echo "$wgcf_sha256  /usr/bin/wgcf" | sha256sum -c - \
    && chmod +x /usr/bin/wgcf \
    && sed -i 's/sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1/echo "skip sysctl src_valid_mark"/' "$(which wg-quick)"
