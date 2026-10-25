# a fixed release: the bot's AdGuard settings are checked against it
FROM adguard/adguardhome:v0.107.79
LABEL org.botlight.project=vpnbot
# security updates of the base image's packages (ca-certificates, openssl, ...)
# on every build, not only what the base image was pulled with
RUN apk upgrade --no-cache \
    && apk add --no-cache --update openssh \
    && mkdir /root/.ssh
ENV ENV="/system/profile"
