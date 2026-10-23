#!/bin/sh
rm -f /ssh/key*
ssh-keygen -m PEM -t rsa -f /ssh/key -N ''
# the other containers only get the public key (./sshpub, read-only)
cp /ssh/key.pub /sshpub/key.pub
# a host key per container, made once: each container gets only its own
# (./sshhost/<name>), the bot checks the public part (/ssh/host_<name>.pub)
for n in up ng ad xr oc wp dnstt service; do
    k=/sshhost/$n/ssh_host_ed25519_key
    mkdir -p /sshhost/$n
    if [ ! -s $k ] || [ ! -s $k.pub ]; then
        rm -f $k $k.pub
        ssh-keygen -q -t ed25519 -N '' -C '' -f $k
    fi
    cp $k.pub /ssh/host_$n.pub
done
openssl req -newkey rsa:2048 -sha256 -nodes -x509 -days 365 -keyout /certs/self_private -out /certs/self_public  -subj "/C=NN/ST=N/L=N/O=N/CN=$IP"
if [ -s /ssh/key.pub ]; then
    php-fpm83 -R -D
    php init.php
else
    exit 1;
fi
