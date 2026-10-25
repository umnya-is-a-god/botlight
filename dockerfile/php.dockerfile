ARG image
FROM $image
# Release binaries are pinned by version and SHA-256: a changed or
# corrupted download fails the build.
ARG dnslookup_version=1.11.1
ARG dnslookup_sha256=daf7b40d498d8ac8a94672b5f95e94d3efac53641a51fa72a5ad776e2cd532f1
ARG singbox_version=1.14.3
# the -musl build: the plain linux-amd64 one is linked against glibc and
# does not run on Alpine
ARG singbox_sha256=41fc81fd041134d4d7d850a928d7d2cde17a7d6563953f406b22d32a68bfab1f
ARG mihomo_version=1.19.32
ARG mihomo_sha256=8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10
# security updates of the base image's packages (ca-certificates, openssl, ...)
# on every build, not only what the base image was pulled with.
# botweb/botadmin: users of the web pools (system/php-fpm.conf); their ids
# are the file groups in ./data (app/storage.php)
RUN apk upgrade --no-cache \
    && apk add --no-cache --update php83 \
    php83-fpm \
    php83-mbstring \
    php83-session \
    php83-phar \
    php83-zip \
    php83-curl \
    php83-opcache \
    php83-openssl \
    php83-iconv \
    php83-intl \
    php83-pecl-ssh2 \
    php83-pecl-yaml \
    php83-sodium \
    xxd \
    certbot \
    libqrencode-tools \
    openssh \
    openssl \
    curl \
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
    && mkdir /tmp/dl && cd /tmp/dl \
    && wget -O dnslookup.tar.gz https://github.com/ameshkov/dnslookup/releases/download/v$dnslookup_version/dnslookup-linux-amd64-v$dnslookup_version.tar.gz \
    && echo "$dnslookup_sha256  dnslookup.tar.gz" | sha256sum -c - \
    && tar -xf dnslookup.tar.gz \
    && mv linux-amd64/dnslookup /usr/bin/ \
    && wget -O sing-box.tar.gz https://github.com/SagerNet/sing-box/releases/download/v$singbox_version/sing-box-$singbox_version-linux-amd64-musl.tar.gz \
    && echo "$singbox_sha256  sing-box.tar.gz" | sha256sum -c - \
    && tar -xf sing-box.tar.gz \
    && mv sing-box-$singbox_version-linux-amd64-musl/sing-box /usr/bin/ \
    && wget -O mihomo.gz https://github.com/MetaCubeX/mihomo/releases/download/v$mihomo_version/mihomo-linux-amd64-v$mihomo_version.gz \
    && echo "$mihomo_sha256  mihomo.gz" | sha256sum -c - \
    && gunzip mihomo.gz \
    && mv mihomo /usr/bin/mihomo \
    && chmod +x /usr/bin/mihomo /usr/bin/dnslookup /usr/bin/sing-box \
    && cd / && rm -rf /tmp/dl \
    && sing-box version && mihomo -v && dnslookup --version
