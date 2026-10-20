ARG image
FROM $image
ARG xray_version
RUN apk add openssh openssl jq curl \
    && mkdir /root/.ssh \
    && wget -O Xray-linux-64.zip https://github.com/XTLS/Xray-core/releases/download/${xray_version}/Xray-linux-64.zip \
    && unzip Xray-linux-64.zip \
    && mv xray /usr/bin/ \
    && rm Xray-linux-64.zip \
    && rm geoip.dat \
    && rm geosite.dat \
    && chmod +x /usr/bin/xray
ENV ENV="/root/.ashrc"
