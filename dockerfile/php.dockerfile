ARG image
FROM $image
RUN apk add --no-cache --update php83 \
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
    xxd \
    certbot \
    libqrencode-tools \
    openssh \
    openssl \
    curl \
    git \
    && ln -sf /usr/bin/php83 /usr/bin/php \
    && mkdir /root/.ssh \
    && wget https://github.com/ameshkov/dnslookup/releases/download/v1.11.1/dnslookup-linux-amd64-v1.11.1.tar.gz \
    && tar -xf dnslookup-linux-amd64-v1.11.1.tar.gz \
    && mv linux-amd64/dnslookup /usr/bin \
    && rm dnslookup-linux-amd64-v1.11.1.tar.gz \
    && rm -rf /linux-amd64 \
    && wget https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz \
    && tar -xf sing-box-1.14.3-linux-amd64.tar.gz \
    && mv sing-box-1.14.3-linux-amd64/sing-box /usr/bin \
    && rm sing-box-1.14.3-linux-amd64.tar.gz \
    && rm -rf /sing-box-1.14.3-linux-amd64 \
    && wget https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-v1.19.32.gz \
    && gunzip mihomo-linux-amd64-v1.19.32.gz \
    && mv mihomo-linux-amd64-v1.19.32 /usr/bin/mihomo \
    && chmod +x /usr/bin/mihomo
