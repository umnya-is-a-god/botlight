ARG image
FROM $image
# makefile: superseded builds are pruned by this label
LABEL org.botlight.project=vpnbot
# XRAY_VERSION (.env): "latest", the newest release at least 3 days old,
# or an exact tag like v26.9.30; the archive is checked against the
# SHA-256 GitHub lists for it (scripts/release.sh)
ARG xray_version
COPY scripts/release.sh /tmp/release.sh
# security updates of the base image's packages (ca-certificates, openssl, ...)
# on every build, not only what the base image was pulled with
RUN --mount=type=secret,id=github_token apk upgrade --no-cache \
    && apk add --no-cache openssh openssl jq curl iptables \
    && mkdir /root/.ssh \
    && case "$xray_version" in v[0-9]*) pick="tag:$xray_version" ;; *) pick=latest:v ;; esac \
    && sh /tmp/release.sh XTLS/Xray-core "$pick" Xray-linux-64.zip /tmp/xray.zip \
    && unzip /tmp/xray.zip xray -d /usr/bin \
    && rm /tmp/xray.zip /tmp/release.sh \
    && chmod +x /usr/bin/xray
ENV ENV="/system/profile"
