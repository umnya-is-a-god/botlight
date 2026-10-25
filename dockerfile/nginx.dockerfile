ARG image
FROM $image
# makefile: superseded builds are pruned by this label
LABEL org.botlight.project=vpnbot
# security updates of the base image's packages (ca-certificates, openssl, ...)
# on every build, not only what the base image was pulled with
RUN apk upgrade --no-cache \
    && apk add --no-cache nginx-mod-stream openssh \
    && mkdir /root/.ssh \
    && mkdir /var/cache/nginx
ENV ENV="/system/profile"
