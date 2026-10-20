ARG image
FROM $image
ARG xray_version
RUN apk add openssh openssl jq curl \
    && mkdir /root/.ssh \
    && if [ -z "$xray_version" ] || [ "$xray_version" = latest ]; \
        then url=https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip; \
        else url=https://github.com/XTLS/Xray-core/releases/download/$xray_version/Xray-linux-64.zip; fi \
    && wget -O Xray-linux-64.zip "$url" \
    && unzip Xray-linux-64.zip \
    && mv xray /usr/bin/ \
    && rm Xray-linux-64.zip \
    && rm geoip.dat \
    && rm geosite.dat \
    && chmod +x /usr/bin/xray
ENV ENV="/root/.ashrc"
