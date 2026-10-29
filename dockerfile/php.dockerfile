ARG image
FROM $image
# makefile: superseded builds are pruned by this label
LABEL org.botlight.project=vpnbot
# dnslookup and sing-box: the newest releases at least 3 days old, checked
# against the SHA-256 GitHub lists for the file (scripts/release.sh).
# sing-box compiles the rule-sets the apps download, and a new minor
# version may change their format: it stays on this series, a move to the
# next one is made here by hand.
ARG singbox_series=v1.14.
COPY scripts/release.sh /tmp/release.sh
# security updates of the base image's packages (ca-certificates, openssl, ...)
# on every build, not only what the base image was pulled with.
# botweb/botadmin: users of the web pools (system/php-fpm.conf); their ids
# are the file groups in ./data (app/storage.php)
RUN --mount=type=secret,id=github_token apk upgrade --no-cache \
    && apk add --no-cache --update php83 \
    php83-fpm \
    php83-mbstring \
    php83-session \
    php83-curl \
    php83-opcache \
    php83-openssl \
    php83-intl \
    php83-pecl-ssh2 \
    php83-pecl-yaml \
    php83-sodium \
    certbot \
    logrotate \
    libqrencode-tools \
    openssh \
    openssl \
    git \
    && ln -sf /usr/bin/php83 /usr/bin/php \
    && mkdir /root/.ssh \
    && addgroup -g 10080 botweb \
    && adduser -D -H -h /nonexistent -s /sbin/nologin -u 10080 -G botweb botweb \
    && addgroup -g 10082 botsecret \
    && addgroup -g 10081 botadmin \
    && adduser -D -H -h /nonexistent -s /sbin/nologin -u 10081 -G botadmin botadmin \
    && addgroup botadmin botweb \
    && addgroup botadmin botsecret \
    && apk add --no-cache --virtual .fetch-deps curl jq \
    && mkdir /tmp/dl && cd /tmp/dl \
    && sh /tmp/release.sh ameshkov/dnslookup latest:v 'dnslookup-linux-amd64-{tag}.tar.gz' dnslookup.tar.gz \
    && tar -xf dnslookup.tar.gz \
    && mv linux-amd64/dnslookup /usr/bin/ \
    && sh /tmp/release.sh SagerNet/sing-box "latest:$singbox_series" 'sing-box-{v}-linux-amd64-musl.tar.gz' sing-box.tar.gz \
    && tar -xf sing-box.tar.gz \
    && mv sing-box-*-linux-amd64-musl/sing-box /usr/bin/ \
    && chmod +x /usr/bin/dnslookup /usr/bin/sing-box \
    && cd / && rm -rf /tmp/dl /tmp/release.sh \
    && apk del .fetch-deps \
    && sing-box version && dnslookup --version
