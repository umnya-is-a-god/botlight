rm /ssh/key*
ssh-keygen -m PEM -t rsa -f /ssh/key -N ''
openssl req -newkey rsa:2048 -sha256 -nodes -x509 -days 365 -keyout /certs/self_private -out /certs/self_public  -subj "/C=NN/ST=N/L=N/O=N/CN=$IP"
if [[ -f "/ssh/key.pub" && -s "/ssh/key.pub" ]]; then
    php-fpm83 -R -D
    php init.php
else
    exit 1;
fi
