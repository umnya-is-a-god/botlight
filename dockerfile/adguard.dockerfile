# the latest release on every build (make rebuild pulls it)
FROM adguard/adguardhome
LABEL org.botlight.project=vpnbot
# security updates of the base image's packages (ca-certificates, openssl, ...)
# on every build, not only what the base image was pulled with
RUN apk upgrade --no-cache \
    && apk add --no-cache --update openssh \
    && mkdir /root/.ssh
ENV ENV="/system/profile"
