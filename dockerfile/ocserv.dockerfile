ARG image
FROM $image
# ocserv builds with meson since 1.4; release tarball pinned and checked
# against the sha512 from the Alpine aports recipe (testing/ocserv)
ARG ocserv_version=1.6.0
ARG ocserv_sha512=512d882b025d157023d0d658a19fbc5f9ecbee9949cd43f3e785e694c97c8c21200a396a64b8990bd9d332e713bfd85e4b2935969755280864b5bc73520f740c
RUN apk add --no-cache openssh \
    iptables \
    gnutls-dev \
    libev-dev \
    linux-pam-dev \
    lz4-dev \
    libseccomp-dev \
    libnl3-dev \
    readline-dev \
    libtasn1-dev \
    talloc-dev \
    protobuf-c-dev \
    llhttp-dev \
    && apk add --no-cache --virtual .build-deps \
    build-base \
    linux-headers \
    meson \
    gperf \
    protobuf-c-compiler \
    xz \
    libtasn1-progs \
    && cd /tmp \
    && wget https://www.infradead.org/ocserv/download/ocserv-${ocserv_version}.tar.xz \
    && echo "${ocserv_sha512}  ocserv-${ocserv_version}.tar.xz" | sha512sum -c - \
    && tar -xf ocserv-${ocserv_version}.tar.xz \
    && cd ocserv-${ocserv_version} \
    && meson setup build --prefix=/usr --buildtype=release \
    && ninja -C build \
    && ninja -C build install \
    && cd / \
    && rm -rf /tmp/ocserv-* \
    && apk del .build-deps \
    && mkdir /root/.ssh
