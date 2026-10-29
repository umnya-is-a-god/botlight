ARG image
FROM $image
# makefile: superseded builds are pruned by this label
LABEL org.botlight.project=vpnbot
# microsocks is built from a fixed commit; wgcf is the newest release at
# least 3 days old, checked against the SHA-256 GitHub lists for the file
# (scripts/release.sh)
ARG microsocks_commit=307950cb1296b521fe86384fd695062ade5304b5
COPY scripts/release.sh /tmp/release.sh
# security updates of the base image's packages (ca-certificates, openssl, ...)
# on every build, not only what the base image was pulled with
RUN --mount=type=secret,id=github_token apk upgrade --no-cache \
    && apk add --no-cache --virtual .build-deps alpine-sdk git curl jq \
    && apk add --no-cache iproute2 iptables openssh wireguard-tools bash \
    && git init -q /tmp/microsocks \
    && git -C /tmp/microsocks fetch -q --depth 1 https://github.com/rofl0r/microsocks $microsocks_commit \
    && git -C /tmp/microsocks checkout -q FETCH_HEAD \
    && [ "$(git -C /tmp/microsocks rev-parse HEAD)" = "$microsocks_commit" ] \
    && make -C /tmp/microsocks \
    && mv /tmp/microsocks/microsocks /usr/bin/microsocks \
    && rm -rf /tmp/microsocks \
    && sh /tmp/release.sh ViRb3/wgcf latest:v 'wgcf_{v}_linux_amd64' /usr/bin/wgcf \
    && rm /tmp/release.sh \
    && apk del .build-deps \
    && mkdir /root/.ssh \
    && chmod +x /usr/bin/wgcf \
    && sed -i 's/sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1/echo "skip sysctl src_valid_mark"/' "$(which wg-quick)"
