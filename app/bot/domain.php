<?php

// Domains, certificates, nginx configs, cover page: methods of class Bot (app/bot.php)
trait BotDomain
{
    // upstream.conf (nginx stream in up) in the current format
    public function upstreamConf(string $t): string
    {
        // the include sits next to it in /etc/nginx/bot (./data/up)
        $t = str_replace('include /etc/nginx/deny;', 'include /etc/nginx/bot/deny;', $t);
        // no UDP here: DTLS goes to ocserv directly (docker-compose.yml);
        // nginx cannot read the name of a DTLS handshake and ocserv takes
        // no proxy protocol over UDP
        return preg_replace('~\n[ \t]*server\s*\{\s*listen\s+443\s+udp;[^{}]*\}[ \t]*(?=\n)~', '', $t);
    }

    public function addOverrideHtml()
    {
        $this->prompt($this->i18n('attach html'), $this->i18n('attach html'), 'setOverrideHtml');
    }

    /**
     * Cover page: nginx shows /app/webapp/override.html at the site root
     * ("/") instead of the login prompt.
     */
    public function setOverrideHtml($text = '')
    {
        $name = (string) ($this->input['file_name'] ?? '');
        if (empty($this->input['file_id']) || !preg_match('~\.html?$~i', $name)) {
            $this->send($this->input['chat'], 'send an .html file');
            return $this->menu('config');
        }
        $r = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        if (($r['result']['file_size'] ?? 0) > 1048576) {
            $this->send($this->input['chat'], 'the page is over 1 MB');
            return $this->menu('config');
        }
        $f = file_get_contents($this->file . $r['result']['file_path']);
        if (!empty($f)) {
            bot_write(BOT_DATA . '/www/override.html', $f, 0644);
        }
        $this->menu('config');
    }

    public function delOverrideHtml()
    {
        @unlink(BOT_DATA . '/www/override.html');
        $this->menu('config');
    }

    public function checkCert()
    {
        try {
            $c = $this->config();
            if (!empty($c['admin']) && date('H') == 12 && (empty($this->time2) || ((time() - $this->time2) > 4600))) {
                $this->time2 = time();
                $cert = $this->expireCert();
                if (!empty($cert) && $cert - 60 * 60 * 24 * 14 < time()) {
                    foreach ($c['admin'] as $k => $v) {
                        $this->send($v, "certificate expire: " . date('Y-m-d H:i:s', $cert));
                    }
                }
            }
        } catch (Throwable $e) {
            error_log("checkCert: $e");
        }
    }

    public function addNipdomain()
    {
        $this->addDomain(str_replace('.', '-', $this->ip) . '.nip.io');
    }

    public function addDomain($domain, $nomenu = false)
    {
        $domain = trim((string) $domain);
        if ($domain !== '' && !$this->validHost($domain = (string) idn_to_ascii($domain))) {
            $this->send($this->input['chat'], 'wrong domain');
            $domain = '';
        }
        if (!empty($domain)) {
            $conf = $this->getPacConf();
            $conf['domain'] = $domain;
            $this->setPacConf($conf);
            $this->chocdomain($domain);
            $this->setUpstreamDomainOcserv($domain);
            $this->cloakNginx();
            // a Let's Encrypt certificate follows the domain
            if (($conf['letsencrypt'] ?? '') === 'letsencrypt' && empty($nomenu)) {
                $this->certTask(false);
            }
        }
        if (empty($nomenu)) {
            $this->menu('config');
        }
    }

    public function sslip()
    {
        $c     = $this->config();
        $p     = $this->getPacConf();
        $ip    = $this->ip;
        // none yet on a fresh install: the first to write to the bot
        $admin = (int) ($c['admin'][0] ?? 0);
        // started by scripts/update.sh (update, restart, images): it sends
        // its report and then the menu (menuAfterHost), so not here too
        $host = is_file('/update/restarting');
        @unlink('/update/restarting');
        $r     = $admin && !$host ? $this->send($admin, "start $ip") : [];

        $this->input['chat']        = $admin;
        $this->input['message_id']  = $r['result']['message_id'] ?? 0;
        $this->input['callback_id'] = false;
        if (empty(array_diff_key($p, array_flip(['hashbot', 'oc_domain', 'adminhash', 'restart'])))) {
            // a fresh install: a nip.io name and a certificate for it
            $this->addDomain(str_replace('.', '-', $this->ip) . '.nip.io', 1);
            $this->certTask(false, $admin);
        }
        if (!$host) {
            $this->menu();
        }
    }

    public function deleteSSL($notmenu = false)
    {
        @unlink('/certs/cert_private');
        @unlink('/certs/cert_public');
        $conf = $this->getPacConf();
        unset($conf['letsencrypt']);
        $this->setPacConf($conf);
        $this->adguardSync();
        $this->cloakNginx();
        if (!$notmenu) {
            $this->menu('config');
        }
    }

    /**
     * The certificate buttons. letsencrypt: a new certificate now (renew
     * SSL works with --force-renewal; with more than 30 days left it asks
     * first: Let's Encrypt limits new certificates per week). self: the
     * file the admin sent (see selfsslInstall).
     */
    public function setSSL($name, $yes = false)
    {
        $conf = $this->getPacConf();
        switch ($name) {
            case 'letsencrypt':
                if (empty($conf['domain'])) {
                    return $this->menu('config');
                }
                $left = ($this->certTimes()['to'] ?? 0) - time();
                if (empty($yes) && ($conf['letsencrypt'] ?? '') === 'letsencrypt' && $left > 30 * 86400) {
                    return $this->update($this->input['chat'], $this->input['message_id'], $this->i18n('renew SSL') . "\n\n"
                        . 'The certificate is valid for ' . floor($left / 86400) . " more days and renews by itself (when a third of its lifetime is left).\n"
                        . "Let's Encrypt allows only a few new certificates for the same names per week. Renew now anyway?", [
                            [['text' => $this->i18n('renew SSL'), 'callback_data' => '/setSSL letsencrypt yes']],
                            [['text' => $this->i18n('back'), 'callback_data' => '/menu config']],
                        ]);
                }
                $this->certTask(true);
                $this->answer($this->input['callback_id'], 'certbot started: a message follows when it ends', true);
                return $this->menu('config');
            case 'self':
                $r = $this->request('getFile', ['file_id' => $this->input['file_id']]);
                if (($r['result']['file_size'] ?? 0) > 1048576) {
                    $this->send($this->input['chat'], 'the file is over 1 MB');
                    return $this->menu('config');
                }
                $bundle = (string) @file_get_contents($this->file . ($r['result']['file_path'] ?? ''));
                [$key, $chain, $err] = $this->parseCertBundle($bundle, (string) ($conf['domain'] ?? ''));
                if ($err !== '') {
                    $this->send($this->input['chat'], htmlspecialchars($err));
                    return $this->menu('config');
                }
                $this->installCert($key, $chain, 'self');
                $this->send($this->input['chat'], 'certificate installed, valid till ' . date('Y-m-d H:i', $this->certTimes()['to'] ?? 0));
                return $this->menu('config');
        }
        $this->menu('config');
    }

    // names the certificate covers: the domain, the OpenConnect and the DoT names
    public function certDomains(): array
    {
        $conf = $this->getPacConf();
        if (empty($conf['domain']) || !$this->validHost($conf['domain'])) {
            return [];
        }
        $oc = $this->getHashSubdomain('oc');
        return array_values(array_filter([
            $conf['domain'],
            $oc ? "$oc.{$conf['domain']}" : '',
            !empty($conf['adguardkey']) ? "{$conf['adguardkey']}.{$conf['domain']}" : '',
        ]));
    }

    /**
     * certbot in the background (php task.php cert): it can take minutes
     * and the bot answers meanwhile; the result comes as a message to
     * $chat (the main admin by default). $force: a new certificate even if
     * the current one is not due.
     */
    public function certTask(bool $force = false, int $chat = 0)
    {
        $chat = $chat ?: (int) ($this->input['chat'] ?? 0);
        exec('cd /app && nohup php task.php cert ' . ($force ? 'force' : 'due') . ' ' . (int) $chat . ' > /dev/null 2>&1 &');
    }

    /**
     * Gets a Let's Encrypt certificate (certbot certonly with the same
     * --cert-name every time: a new one for the current names, or a renewal
     * of the lineage in ./data/letsencrypt) and installs it. Without
     * $force certbot changes nothing if the names are the same and the
     * certificate is not due. Runs in task.php.
     */
    public function renewCert(bool $force, int $chat = 0): bool
    {
        $c       = $this->config();
        $chat    = $chat ?: (int) ($c['admin'][0] ?? 0);
        $domains = $this->certDomains();
        if (!$domains) {
            return false;
        }
        // no email: not needed to get or renew the certificate
        $email = '--register-unsafely-without-email';
        $args  = implode(' ', array_map(fn($e) => '-d ' . escapeshellarg($e), $domains));
        @mkdir('/acme', 0755);
        exec('certbot certonly --cert-name ' . escapeshellarg($domains[0]) . ' --expand --renew-with-new-domains ' . ($force ? '--force-renewal ' : '')
            . "--preferred-chain 'ISRG Root X1' -n --agree-tos $email $args --webroot -w /acme --logs-dir /logs --max-log-backups 0 2>&1", $out, $code);
        if ($code > 0) {
            $this->send($chat, "certificate: certbot failed\n<pre>" . htmlspecialchars(implode("\n", array_slice($out, -30))) . '</pre>');
            return false;
        }
        $live  = "/etc/letsencrypt/live/{$domains[0]}";
        $key   = bot_read("$live/privkey.pem");
        $chain = bot_read("$live/fullchain.pem");
        if (trim($chain) === trim((string) @file_get_contents('/certs/cert_public')) && ($this->getPacConf()['letsencrypt'] ?? '') === 'letsencrypt') {
            if ($force) {
                $this->send($chat, 'certificate: nothing to renew');
            }
            return true;
        }
        $this->installCert($key, $chain, 'letsencrypt');
        $this->send($chat, 'certificate installed: ' . htmlspecialchars(implode(', ', $domains)) . ', valid till ' . date('Y-m-d H:i', $this->certTimes()['to'] ?? 0));
        return true;
    }

    /**
     * Once a day (cron): a Let's Encrypt certificate is renewed when a third
     * of its lifetime is left (30 days of 90; the share also fits shorter
     * certificates).
     */
    public function checkCertRenew()
    {
        $conf = $this->getPacConf();
        if (($conf['letsencrypt'] ?? '') !== 'letsencrypt' || empty($conf['domain'])) {
            return;
        }
        $day = date('Y-m-d');
        if (($this->getState()['cert_checked'] ?? '') === $day) {
            return;
        }
        $this->updateState(function ($st) use ($day) {
            $st['cert_checked'] = $day;
            return $st;
        });
        $t = $this->certTimes();
        if (empty($t['to']) || empty($t['from']) || $t['to'] - time() < ($t['to'] - $t['from']) / 3) {
            $this->certTask(true, (int) ($this->config()['admin'][0] ?? 0));
            return;
        }
        // a name the certificate lacks (a ClientID from a restored backup,
        // a failed request): one new certificate per set of names, so a
        // name certbot cannot get is not retried every day (renew SSL can)
        $names   = $this->certDomains();
        $certs   = $this->domainsCert() ?: [];
        $missing = array_filter($names, fn($e) => !$this->certCovers($e, $certs));
        $key     = implode(' ', $names);
        if ($missing && ($this->getState()['cert_names_tried'] ?? '') !== $key) {
            $this->updateState(function ($st) use ($key) {
                $st['cert_names_tried'] = $key;
                return $st;
            });
            $this->certTask(false, (int) ($this->config()['admin'][0] ?? 0));
        }
    }

    /**
     * Puts a certificate in place: /certs/cert_private (root only) and
     * /certs/cert_public, then nginx, AdGuard and ocserv take it.
     */
    public function installCert(string $key, string $chain, string $type)
    {
        $conf = $this->getPacConf();
        $conf['letsencrypt'] = $type;
        $this->setPacConf($conf);
        bot_write('/certs/cert_private', $key, 0600);
        bot_write('/certs/cert_public', $chain, 0644);
        $this->adguardSync();
        $this->cloakNginx();
        // ocserv reads the certificate again on reload
        $this->ssh('occtl reload', 'oc');
    }

    /**
     * Checks a certificate file (chain and private key): the key may be RSA,
     * EC or PKCS#8 (not encrypted), it must match the certificate, which
     * must be valid now and cover $domain. Returns [key, chain, error]: the
     * key as PKCS#8, the chain with the certificate first.
     */
    public function parseCertBundle(string $bundle, string $domain): array
    {
        if (preg_match('~-----BEGIN ENCRYPTED PRIVATE KEY-----~', $bundle)) {
            return ['', '', 'the private key is encrypted: send it without a password'];
        }
        if (!preg_match('~-----BEGIN ((?:RSA |EC )?PRIVATE KEY)-----.+?-----END \1-----~s', $bundle, $m)) {
            return ['', '', 'no private key in the file (BEGIN PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY)'];
        }
        $pkey = openssl_pkey_get_private($m[0]);
        if ($pkey === false || !openssl_pkey_export($pkey, $key)) {
            return ['', '', 'the private key cannot be read'];
        }
        preg_match_all('~-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----~s', $bundle, $m);
        $leaf = null;
        foreach ($m[0] as $k => $pem) {
            $x = openssl_x509_read($pem);
            if ($x !== false && openssl_x509_check_private_key($x, $pkey)) {
                $leaf = $k;
                break;
            }
        }
        if ($leaf === null) {
            return ['', '', !empty($m[0]) ? 'the private key does not belong to any certificate in the file' : 'no certificate in the file'];
        }
        $info = openssl_x509_parse($m[0][$leaf]);
        if (($info['validTo_time_t'] ?? 0) <= time()) {
            return ['', '', 'the certificate has expired: ' . date('Y-m-d H:i', $info['validTo_time_t'] ?? 0)];
        }
        if (($info['validFrom_time_t'] ?? 0) > time() + 300) {
            return ['', '', 'the certificate is not valid yet: from ' . date('Y-m-d H:i', $info['validFrom_time_t'])];
        }
        $names = array_map(fn($e) => strtolower(trim(preg_replace('~^DNS:~', '', trim($e)))), explode(',', (string) ($info['extensions']['subjectAltName'] ?? '')));
        $covers = function ($host) use ($names) {
            $host = strtolower($host);
            foreach ($names as $n) {
                if ($n === $host || (str_starts_with($n, '*.') && substr($host, strpos($host, '.')) === substr($n, 1))) {
                    return true;
                }
            }
            return false;
        };
        if ($domain !== '' && !$covers($domain)) {
            return ['', '', "the certificate does not cover $domain (names: " . implode(', ', array_filter($names)) . ')'];
        }
        $chain = $m[0];
        $first = $chain[$leaf];
        unset($chain[$leaf]);
        return [$key, implode("\n", array_merge([$first], $chain)) . "\n", ''];
    }

    // validity of the installed certificate: ['from' => time, 'to' => time], [] if none
    public function certTimes(): array
    {
        $pem = @file_get_contents('/certs/cert_public');
        $x   = $pem ? @openssl_x509_read($pem) : false;
        $i   = $x ? openssl_x509_parse($x) : false;
        return $i ? ['from' => (int) $i['validFrom_time_t'], 'to' => (int) $i['validTo_time_t']] : [];
    }

    public function delDomain()
    {
        $this->deleteSSL(1);
        $conf = $this->getPacConf();
        unset($conf['domain']);
        $this->setPacConf($conf);
        $this->setUpstreamDomainOcserv('');
        $this->chocdomain('');
        $this->adguardSync();
        $this->cloakNginx();
        $this->menu('config');
    }

    public function domain()
    {
        $this->prompt($this->i18n('enter domain'), $this->i18n('enter domain'), 'addDomain');
    }

    public function selfssl()
    {
        $this->prompt($this->i18n('prompt selfssl'), $this->i18n('send file with your certificate chain and private key'), 'selfsslInstall');
    }

    public function addLinkDomain()
    {
        $this->prompt($this->i18n('enter domain for link'), $this->i18n('enter domain for link'), 'setLinkDomain');
    }

    public function setLinkDomain($text)
    {
        $c    = $this->getPacConf();
        $text = trim((string) $text);
        if ($text !== '' && !$this->validHost($text = (string) idn_to_ascii($text))) {
            $this->send($this->input['chat'], 'wrong domain');
            return $this->xray();
        }
        if ($text === '') {
            unset($c['linkdomain']);
        } else {
            $c['linkdomain'] = $text;
        }
        $this->setPacConf($c);
        $this->xray();
    }

    public function selfsslInstall()
    {
        $this->setSSL('self');
    }


    public function setUpstreamDomain($domain)
    {
        // written into the nginx stream config: host names only
        if (!$this->validHost($domain)) {
            return;
        }
        $nginx = bot_read(BOT_DATA . '/up/upstream.conf');
        $t = preg_replace('~#domain.+#domain~s', "#domain\n$domain reality;\n#domain", $this->upstreamConf($nginx));
        $this->applyUpstream($t);
    }

    // upstream.conf, if nginx in up accepts it, and reload
    public function applyUpstream(string $t)
    {
        if ($this->applyConfig(BOT_DATA . '/up/upstream.conf', $t, 'up', 'nginx -t -q -c %s')) {
            $this->ssh(self::NGINX_UP . ' -s reload 2>&1', 'up');
        }
    }

    // nginx.conf for ng, made from the template config/nginx_default.conf
    public function nginxConf(): string
    {
        $conf     = $this->getPacConf();
        if (!empty($conf['domain']) && !$this->validHost($conf['domain'])) {
            $conf['domain'] = '';
        }
        $template = bot_read('/config/nginx_default.conf');
        // $template = preg_replace('~server_name ip~', "server_name {$this->ip}", $template);
        $template = preg_replace('~server_name domain~', "server_name " . (!empty($conf['domain']) ? " *.{$conf['domain']} {$conf['domain']}" : '_'), $template);
        if (!empty($conf['domain']) && !empty($conf['letsencrypt'])) {
            $template = preg_replace('/#~([^\n]+)?/', "#~{$conf['letsencrypt']}", $template);
            preg_match_all('~#-domain.+?#-domain~s', $template, $m);
            foreach ($m[0] as $v) {
                $template = preg_replace('~#-domain.+?#-domain~s', $this->uncomment($v, 'domain'), $template, 1);
            }
        }
        $h  = $this->getHashBot();
        // the cookie values and AdGuard's login: adguard.conf (adguardInclude)
        $r = <<<CONF
        location /adguard/ {
                # client addresses only: the path carries the admin hash
                access_log /logs/nginx_adguard_access ip_only;
                if (\$adguard_ok = 0) {
                    rewrite .* /webapp redirect;
                }
                proxy_set_header Authorization \$adguard_auth;
                proxy_set_header Cookie "";
                proxy_pass http://ad/;
                proxy_redirect / /adguard/;
                proxy_cookie_path / /adguard/;
            }
            location
        CONF;
        $template = preg_replace('~(location /adguard.+?})\s*location~s', $r, $template);
        // the Mini App and the AdGuard panel under their own secret: the
        // path hash is in every subscriber's links
        $template = preg_replace('~(/webapp|/adguard)(?=[\s/;{])~', '${1}' . $this->getAdminHash(), $template);
        return preg_replace('~(/pac|/ws|location /dns-query)(?=[\s/;{])~', '${1}' . $h, $template);
    }

    /**
     * Writes nginx.conf and keeps Xray's path in line with it. $reload:
     * reload nginx and restart Xray if its path changed; false while the
     * containers are not up yet (before the start, see prepare()).
     */
    public function cloakNginx($reload = true)
    {
        $this->writeAdguardInclude($reload);
        if (!$this->applyConfig(BOT_DATA . '/ng/nginx.conf', $this->nginxConf(), 'ng', 'nginx -t -q -c %s')) {
            return '';
        }
        $h       = $this->getHashBot();
        $x       = $this->getXray();
        $changed = false;
        foreach (['wsSettings', 'xhttpSettings'] as $k) {
            if (!empty($x['inbounds'][0]['streamSettings'][$k]['path']) && $x['inbounds'][0]['streamSettings'][$k]['path'] !== "/ws$h") {
                $x['inbounds'][0]['streamSettings'][$k]['path'] = "/ws$h";
                $changed = true;
            }
        }
        if ($changed) {
            $this->restartXray($x, !$reload);
        }
        return $reload ? $this->ssh(self::NGINX_NG . ' -s reload', 'ng') : '';
    }

    public function expireCert()
    {
        return $this->certTimes()['to'] ?? false;
    }

    /**
     * The domain lines of the menus: the bot's names with their
     * certificate's expiry, or a note when the installed certificate does
     * not cover the name (Settings -> renew SSL gets one with it)
     */
    public function domainLines(): array
    {
        $conf  = $this->getPacConf();
        $oc    = $this->getHashSubdomain('oc');
        $certs = $this->domainsCert() ?: [];
        $to    = (int) $this->expireCert();
        $note  = fn($name) => $this->certCovers($name, $certs)
            ? ' (ssl: ' . date('Y-m-d H:i:s', $to) . ')'
            : ($certs ? ' (not in the certificate)' : '');
        $lines = ['Domains:', $conf['domain'] . $note($conf['domain'])];
        if (!empty($oc)) {
            $lines[] = "openconnect $oc.{$conf['domain']}" . $note("$oc.{$conf['domain']}");
        }
        if (!empty($conf['adguardkey'])) {
            $lines[] = "{$conf['adguardkey']}.{$conf['domain']}" . $note("{$conf['adguardkey']}.{$conf['domain']}") . ' adguard DOT';
        }
        return $lines;
    }

    // a name the certificate's names cover: itself, or a wildcard one level up
    public function certCovers(string $name, array $certs): bool
    {
        $parent = substr($name, strpos($name, '.') + 1);
        return in_array($name, $certs, true) || in_array("*.$parent", $certs, true);
    }

    public function domainsCert()
    {
        $pem = @file_get_contents('/certs/cert_public');
        $x   = $pem ? @openssl_x509_read($pem) : false;
        $domains = $x ? (openssl_x509_parse($x)['extensions']['subjectAltName'] ?? '') : '';
        if (empty($domains)) {
            return false;
        }
        return array_map(fn($e) => trim($e), explode(',', str_replace('DNS:', '', $domains)));
    }

    /**
     * The certificate nginx serves the domain with: letsencrypt, self, or
     * '' (none: links use http). Taken from the settings nginx.conf is made
     * from (nginxConf()), so the web pools need no access to nginx.conf.
     */
    public function nginxGetTypeCert()
    {
        $p = $this->getPacConf();
        return !empty($p['domain']) && $this->validHost($p['domain']) && !empty($p['letsencrypt']) ? (string) $p['letsencrypt'] : '';
    }
}
