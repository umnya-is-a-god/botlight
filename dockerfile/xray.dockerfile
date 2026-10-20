ARG image
FROM $image
ARG xray_version
# The release archive is checked against the SHA-256 published with the
# same release (.dgst): catches corrupted or swapped downloads.
RUN apk add openssh openssl jq curl iptables \
    && mkdir /root/.ssh \
    && if [ -z "$xray_version" ] || [ "$xray_version" = latest ]; \
        then url=https://github.com/XTLS/Xray-core/releases/latest/download; \
        else url=https://github.com/XTLS/Xray-core/releases/download/$xray_version; fi \
    && wget -O Xray-linux-64.zip "$url/Xray-linux-64.zip" \
    && wget -O Xray-linux-64.zip.dgst "$url/Xray-linux-64.zip.dgst" \
    && sum=$(sed -n 's/^SHA2-256= *//p' Xray-linux-64.zip.dgst | tr -d '\r ') \
    && [ ${#sum} -eq 64 ] \
    && echo "$sum  Xray-linux-64.zip" | sha256sum -c - \
    && unzip Xray-linux-64.zip xray \
    && mv xray /usr/bin/ \
    && rm Xray-linux-64.zip Xray-linux-64.zip.dgst \
    && chmod +x /usr/bin/xray
ENV ENV="/root/.ashrc"
