<?php

// AdGuard Home: config, users, panel access, upstreams: methods of class Bot (app/bot.php)
trait BotAdguard
{
    // AdGuard's config; an exception if it cannot be read or parsed
    public function getAdguard(): array
    {
        $c = yaml_parse(bot_read($this->adguard));
        if (!is_array($c)) {
            throw new RuntimeException("damaged {$this->adguard}");
        }
        return $c;
    }

    // AdGuard's config, if AdGuard accepts it (--check-config in ad)
    public function saveAdguard(array $c): bool
    {
        $y = yaml_emit($c);
        if (!is_string($y) || $y === '') {
            throw new RuntimeException("cannot encode {$this->adguard}");
        }
        $ok = $this->applyConfig($this->adguard, $y, 'ad', 'd=$(mktemp -d); /opt/adguardhome/AdGuardHome --check-config --no-permcheck --no-check-update -c %s -w "$d" > /dev/null; r=$?; rm -rf "$d"; [ $r -eq 0 ]');
        $this->adguardChanged = $this->adguardChanged || $ok;
        return $ok;
    }

    public function adguardSync()
    {
        $pac  = $this->getPacConf();
        $pass = $this->secret('adpswd');
        if ($pass === '') {
            $this->setSecret('adpswd', $pass = bin2hex(random_bytes(8)));
        }
        $ssl  = $this->nginxGetTypeCert();
        $orig = $this->getAdguard();
        $c    = $orig;
        // the hash stays while the password is the same: a new salt would
        // change the config, and AdGuard would restart for nothing
        $hash = function (string $name, string $password, $algo, array $opt = []) use ($orig) {
            foreach ($orig['users'] ?? [] as $u) {
                if (($u['name'] ?? '') === $name && is_string($u['password'] ?? null) && password_verify($password, $u['password'])) {
                    return $u['password'];
                }
            }
            return password_hash($password, $algo, $opt);
        };
        $c['users'] = [
            ['name' => 'admin', 'password' => $hash('admin', $pass, PASSWORD_DEFAULT)],
            // nginx's login (writeAdguardInclude): a long random password, so
            // a fast hash is enough; AdGuard checks it on every request
            ['name' => 'bot', 'password' => $hash('bot', $this->adguardProxyPassword(), PASSWORD_BCRYPT, ['cost' => 4])],
        ];
        $c = $this->adguardClientsConf($c);
        if (!empty($ssl) && !empty($pac['domain']) && empty($c['tls']['enabled'])) {
            $c['tls']['enabled']     = true;
            $c['tls']['server_name'] = $pac['domain'];
        }
        if ($c === $orig) {
            // nothing to change: AdGuard keeps running
            return;
        }
        $this->stopAd();
        $this->saveAdguard($c);
        $this->startAd();
    }

    public function adguardpsswd()
    {
        $this->prompt($this->i18n('enter password'), $this->i18n('enter password'), 'chpsswd');
    }

    public function setAdguardKey()
    {
        $this->prompt('ClientID: a-z, 0-9 and - inside, up to 63; <code>-</code> deletes it', $this->i18n('enter key'), 'setAdKey');
    }

    public function setAdKey($key)
    {
        $key = strtolower(trim((string) $key));
        $c   = $this->getPacConf();
        if ($key === '-') {
            // DoH/DoT without a ClientID again; the certificate keeps the
            // name until it is renewed, which does no harm
            unset($c['adguardkey']);
            $this->setPacConf($c);
            $this->adguardSync();
            $this->menu('adguard');
            return;
        }
        // a DNS label: it is the DoT name's subdomain and goes into the
        // certificate and the AdGuard config
        if (!preg_match('~^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$~D', $key)) {
            $this->send($this->input['chat'], 'wrong ClientID: a-z, 0-9 and - inside, up to 63; - deletes it');
            return;
        }
        $c['adguardkey'] = $key;
        $this->setPacConf($c);
        // AdGuard's allowed clients take the new ClientID now, not at the next restart
        $this->adguardSync();
        // the DoT name is in the certificate: a new one with it
        if (($c['letsencrypt'] ?? '') === 'letsencrypt') {
            $this->certTask(false);
            $this->send($this->input['chat'], 'the certificate is renewed for the new name: a message follows');
        }
        $this->menu('adguard');
    }

    public function chpsswd($pass)
    {
        if (!preg_match('~^[^\x00-\x1f\x7f]{8,128}$~uD', $pass = trim((string) $pass))) {
            $this->send($this->input['chat'], 'wrong password: 8-128 printable characters');
            return $this->menu('adguard');
        }
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $out[] = $this->stopAd();
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $c = $this->getAdguard();
        $c['users'][0]['password'] = password_hash($pass, PASSWORD_DEFAULT);
        $this->saveAdguard($c);
        $this->setSecret('adpswd', $pass);
        $this->startAd();
        $this->menu('adguard');
    }

    public function adguardreset()
    {
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        // the default config: the template in /config
        $default = @file_get_contents('/config/AdGuardHome.yaml');
        if (!empty($default) && is_array(yaml_parse($default))) {
            bot_write($this->adguard, $default);
        }
        $this->adguardSync();
        $this->cloakNginx();
        $this->menu('adguard');
    }

    /**
     * AdGuard's clients from the Xray users (persistent clients named after
     * them, the user id as ClientID) and the allowed_clients list (on by
     * default): the internal networks, OpenConnect clients, the DoT
     * ClientID and the users switched on. Called on every user change.
     */
    public function adguardClientsConf(array $ad): array
    {
        $tmp = [];
        $ids = [];
        foreach ($this->getXray()['inbounds'][0]['settings']['clients'] ?? [] as $v) {
            $tmp[] = [
                'safe_search' => [
                    'enabled'    => true,
                    'bing'       => true,
                    'duckduckgo' => true,
                    'google'     => true,
                    'pixabay'    => true,
                    'yandex'     => true,
                    'youtube'    => true,
                ],
                'blocked_services' => [
                    'schedule' => ['time_zone' => date_default_timezone_get()],
                    'ids'      => [],
                ],
                'name'                        => $v['email'],
                'ids'                         => [$v['id']],
                'tags'                        => [],
                'upstreams'                   => [],
                'uid'                         => $v['id'],
                'upstreams_cache_size'        => 0,
                'upstreams_cache_enabled'     => false,
                'use_global_settings'         => true,
                'filtering_enabled'           => false,
                'parental_enabled'            => false,
                'safebrowsing_enabled'        => false,
                'use_global_blocked_services' => true,
                'ignore_querylog'             => false,
                'ignore_statistics'           => false,
            ];
            if (empty($v['off'])) {
                $ids[] = $v['id'];
            }
        }
        $ad['clients']['persistent'] = $tmp;
        $pac = $this->getPacConf();
        if (!array_key_exists('adg_allowed', $pac) || !empty($pac['adg_allowed'])) {
            $ad['dns']['allowed_clients'] = array_values(array_unique(array_filter(array_merge(
                ['10.10.0.0/24', '10.0.2.0/24'], // containers, OpenConnect clients
                [$pac['adguardkey'] ?? ''],
                $ids
            ))));
        } else {
            unset($ad['dns']['allowed_clients']);
        }
        return $ad;
    }

    public function adguardXrayClients()
    {
        $this->stopAd();
        $this->saveAdguard($this->adguardClientsConf($this->getAdguard()));
        $this->startAd();
    }

    // allowed_clients on/off (on by default)
    public function adgAllowed()
    {
        $pac = $this->getPacConf();
        $pac['adg_allowed'] = array_key_exists('adg_allowed', $pac) && empty($pac['adg_allowed']);
        $this->setPacConf($pac);
        $this->adguardXrayClients();
        $this->menu('adguard');
    }

    /**
     * The AdGuard panel opens through nginx: /adguard<admin path>/ checks
     * the cookie the Mini App sets (a new value every day, yesterday's
     * still valid) and logs in to AdGuard with Basic auth as a user of its
     * own (AdGuard accepts it when no session cookie is sent), so the
     * admin's password is not needed there. adguard.conf (in ng) holds
     * the cookie values and that login.
     */
    public function adguardInclude(): string
    {
        $day   = (int) floor(time() / 86400);
        $login = base64_encode('bot:' . $this->adguardProxyPassword());
        return "map \$cookie_c \$adguard_ok {\n    default 0;\n    \"{$this->getAdguardCookie($day)}\" 1;\n    \"{$this->getAdguardCookie($day - 1)}\" 1;\n}\n"
            . "map \$host \$adguard_auth {\n    default \"Basic $login\";\n}\n";
    }

    // the AdGuard user nginx logs in with (adguardSync adds it to AdGuard)
    public function adguardProxyPassword(): string
    {
        $p = $this->secret('adguard_proxy');
        if ($p === '') {
            $this->setSecret('adguard_proxy', $p = bin2hex(random_bytes(24)));
        }
        return $p;
    }

    /**
     * adguard.conf for ng, if it changed (a new day: new cookie value) and
     * nginx accepts it, then the Mini App gets today's value and nginx
     * reloads. $reload false: before the containers start.
     */
    public function writeAdguardInclude($reload = true)
    {
        $f   = BOT_DATA . '/ng/adguard.conf';
        $new = $this->adguardInclude();
        if (is_file($f) && bot_read($f) === $new) {
            return;
        }
        $ng = BOT_DATA . '/ng/nginx.conf';
        if (!$reload || !is_file($ng)) {
            bot_write($f, $new);
        } else {
            bot_write("$ng.test", str_replace('include /etc/nginx/bot/adguard.conf;', 'include /etc/nginx/bot/adguard.conf.new;', bot_read($ng)));
            $ok = $this->applyConfig($f, $new, 'ng', 'nginx -t -q -c /etc/nginx/bot/nginx.conf.test');
            @unlink("$ng.test");
            if (!$ok) {
                return;
            }
            $this->ssh(self::NGINX_NG . ' -s reload', 'ng');
        }
        $this->writeWebSecrets();
    }

    public function checkdns()
    {
        $this->prompt($this->i18n('prompt checkdns'), $this->i18n('enter command'), 'dnscheck');
    }

    public function dnscheck($dns)
    {
        exec('JSON=1 dnslookup ' . implode(' ', array_map('escapeshellarg', preg_split('~\s+~', trim($dns)))), $out, $code);
        // a message of its own, the menu goes back in place
        $this->send($this->input['chat'], mb_substr(($code ? '' : "JSON=1 dnslookup $dns\n") . implode("\n", $out), 0, 4000), mode: false);
        $this->menu('adguard');
    }

    public function addupstream()
    {
        $this->prompt($this->i18n('enter address upstream'), $this->i18n('ph: enter address upstream'), 'upstream');
    }

    /**
     * An AdGuard upstream as AdGuard writes them: plain IP[:port] or a
     * tls/https/quic/h3/tcp/udp/sdns URL, optionally for [/domains/] only.
     */
    public function validUpstream($u): bool
    {
        return is_string($u) && (bool) preg_match('~^(?:\[/[A-Za-z0-9.*/_-]+/\])?(?:(?:tls|https|quic|h3|tcp|udp|sdns)://[^\s]+|[0-9A-Fa-f:.\[\]]+)$~D', $u);
    }

    public function upstream($url)
    {
        if (!$this->validUpstream($url = trim((string) $url))) {
            $this->send($this->input['chat'], 'wrong upstream, like 8.8.8.8, tls://dns.quad9.net or https://dns.google/dns-query');
            return $this->menu('adguard');
        }
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $out[] = $this->stopAd();
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $c = $this->getAdguard();
        $c['dns']['upstream_dns'][] = $url;
        $this->saveAdguard($c);
        $this->startAd();
        $this->menu('adguard');
    }

    // $id: shortId() of the upstream; one removed meanwhile changes nothing
    public function delupstream($id)
    {
        $c = $this->getAdguard();
        $k = null;
        foreach ($c['dns']['upstream_dns'] ?? [] as $n => $v) {
            if ($id === $this->shortId((string) $v)) {
                $k = $n;
            }
        }
        if ($k === null) {
            return $this->menu('adguard');
        }
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $this->stopAd();
        $c = $this->getAdguard();
        unset($c['dns']['upstream_dns'][$k]);
        $c['dns']['upstream_dns'] = array_values($c['dns']['upstream_dns']);
        $this->saveAdguard($c);
        $this->startAd();
        $this->menu('adguard');
    }

    /**
     * AdGuard answers: its web interface (ad:80) or plain DNS. The web check
     * keeps the status right when plain DNS is turned off in AdGuard.
     */
    public function adguardUp(): bool
    {
        $ch = curl_init('http://ad/');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_TIMEOUT        => 2,
        ]);
        curl_exec($ch);
        if (curl_getinfo($ch, CURLINFO_HTTP_CODE) > 0) {
            return true;
        }
        return (bool) exec("JSON=1 timeout 2 dnslookup google.com ad");
    }

    /**
     * AdGuard in the background. After a config change it gets 30 seconds
     * to answer; if its process has ended by then, the previous config
     * goes back.
     */
    public function startAd()
    {
        $out = $this->ssh('/opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work', 'ad', false);
        if ($this->adguardChanged) {
            $this->adguardChanged = false;
            // a slow start (first start, a small server) is not a failure
            $until = time() + 30;
            while (!$this->adguardUp() && time() < $until) {
                usleep(500000);
            }
            // back to the previous config only when AdGuard is known to have
            // stopped: the container answers and the process is gone. Not
            // reachable (starting too) or still starting: nothing is undone.
            $gone = !$this->adguardUp()
                && $this->sshRun('p=$(cat /opt/adguardhome/pid 2>/dev/null); [ -n "$p" ] && kill -0 "$p" 2>/dev/null', 'ad')['rc'] === 1;
            if ($gone && $this->rollbackConfig($this->adguard)) {
                $this->stopAd();
                $this->ssh('/opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work', 'ad', false);
                $this->configRejected('AdGuardHome.yaml', 'AdGuard did not start with the new config, the previous one is back');
            }
        }
        return $out;
    }

    // AdGuard stopped: waits until the process has ended (up to 10 s)
    public function stopAd()
    {
        return $this->ssh('p=$(cat /opt/adguardhome/pid 2>/dev/null); [ -n "$p" ] || exit 0; kill -15 "$p"; i=0; while kill -0 "$p" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done', 'ad');
    }

    /**
     * Cookie value that opens the AdGuard panel. Separate from the path hash,
     * which every subscriber sees in their links.
     */
    // the AdGuard panel cookie of a day (by default today's)
    public function getAdguardCookie(?int $day = null): string
    {
        if ($this->web) {
            return (string) ($this->webSecrets()['adguard_cookie'] ?? '');
        }
        return hash_hmac('sha256', 'adguard-cookie|' . ($day ?? (int) floor(time() / 86400)), $this->key);
    }

    public function adguardMenu()
    {
        $conf   = $this->getPacConf();
        $ip     = $this->ip;
        $domain = $this->getDomain();
        $hash   = $this->getHashBot();
        $scheme = empty($ssl = $this->nginxGetTypeCert()) ? 'http' : 'https';
        $admin  = $this->getAdminHash();
        // the password: in the Mini App (secrets); the panel needs none there
        $text   = "$scheme://$domain/adguard$admin\nLogin: admin\nPass: " . $this->mask($this->secret('adpswd')) . "\n\n";
        $ad      = $this->getAdguard();
        $allowed = $ad['dns']['allowed_clients'] ?? [];
        if ($ssl) {
            $text .= "DNS over HTTPS:\n<code>$ip</code>\n<code>$scheme://$domain/dns-query$hash" . (!empty($conf['adguardkey']) ? "/{$conf['adguardkey']}" : '') . "</code>\n\n";
            $text .= "DNS over TLS:\n<code>tls://" . (!empty($conf['adguardkey'] )? "{$conf['adguardkey']}." : '') . "$domain</code>";
            if ($allowed && empty($conf['adguardkey'])) {
                // allowed clients on: DoH/DoT answer only known ClientIDs
                $text .= "\n(allowed clients: set a ClientID to use DoH/DoT outside the VPN; Xray users have theirs in the subscription)";
            }
        }
        $status = $this->i18n($this->adguardUp() ? 'on' : 'off');
        $safesearch = $ad['filtering']['safe_search']['enabled'] ?? false;
        $text .= "\n\nstatus: $status\t\tsafesearch: " . $this->i18n($safesearch ? 'on' : 'off');
        $text .= "\nallowed clients: " . ($allowed ? count($allowed) : $this->i18n('off'));

        $data = [
            [
                [
                    'text'          => $this->i18n('web panel'),
                    'web_app' => [
                        "url" => "https://$domain/webapp$admin/"
                    ],
                ],
            ],
            [
                [
                    'text'          => $this->i18n('change password'),
                    'callback_data' => "/adguardpsswd",
                ],
                $this->secretsButton('adguard'),
                [
                    'text'          => 'ClientID' . (!empty($conf['adguardkey']) ? ": {$conf['adguardkey']}" : ''),
                    'callback_data' => "/setAdguardKey",
                ],
            ],
        ];
        $data[] = [
            [
                // the list follows the Xray users by itself
                'text'          => $this->i18n('allowed clients') . ': ' . $this->i18n($allowed ? 'on' : 'off'),
                'callback_data' => '/adgAllowed',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('check DNS'),
                'callback_data' => "/checkdns",
            ],
            [
                'text'          => $this->i18n('reset settings'),
                'callback_data' => "/adguardreset",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('add upstream'),
                'callback_data' => "/addupstream",
            ],
        ];
        $upstreams = $ad['dns']['upstream_dns'] ?? [];
        if (!empty($upstreams)) {
            foreach ($upstreams as $k => $v) {
                $data[] = [
                    [
                        'text'          => $v,
                        'callback_data' => "/menu adguard",
                    ],
                    [
                        'text'          => $this->i18n('delete'),
                        'callback_data' => '/delupstream ' . $this->shortId((string) $v),
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => $text,
            'data' => $data,
        ];
    }
}
