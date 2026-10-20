ARG image
FROM $image
RUN apk add --no-cache nginx-mod-stream openssh \
    && mkdir /root/.ssh \
    && mkdir /var/cache/nginx
ENV ENV="/root/.ashrc"
