<?php

// OpenConnect (ocserv): config, users, traffic: methods of class Bot (app/bot.php)
trait BotOpenconnect
{
    public function changeCamouflage()
    {
        $this->prompt($this->i18n('enter camouflage key'), $this->i18n('enter camouflage key'), 'chockey');
    }

    public function changeOcDomain()
    {
        $this->prompt($this->i18n('enter subdomain'), $this->i18n('enter subdomain'), 'chOcSubdomain');
    }


    public function changeOcPass()
    {
        $this->prompt($this->i18n('enter pass'), $this->i18n('enter password'), 'chocpass');
    }

    public function addOcUser()
    {
        $this->prompt($this->i18n('enter name'), $this->i18n('enter name'), 'addocus');
    }

    /**
     * ocserv.conf in the current format: the disconnect script that counts
     * the traffic (scripts/oc_disconnect.sh), unless one of its own is set.
     */
    public function ocservConf(string $t): string
    {
        if (preg_match('~^disconnect-script\s*=~m', $t)) {
            return $t;
        }
        $line = 'disconnect-script = /scripts/oc_disconnect.sh';
        $n    = preg_replace('~^#disconnect-script\s*=.*$~m', $line, $t, 1, $count);
        return $count ? $n : rtrim($t) . "\n\n$line\n";
    }

    public function restartOcserv($conf)
    {
        // ocserv -t also loads the certificate: without one it fails
        // anyway, so then the file is only parsed when ocserv starts
        $test = is_file('/certs/cert_public') ? 'ocserv -t -c %s' : 'true';
        if (!$this->applyConfig(BOT_DATA . '/ocserv/ocserv.conf', $this->ocservConf((string) $conf), 'oc', $test)) {
            return false;
        }
        $this->ssh('pkill ocserv', 'oc');
        $pac = $this->getPacConf();
        if ($this->secret('ocserv') !== '' && !empty($this->getHashSubdomain('oc'))) {
            $this->ssh('ocserv -c /etc/ocserv/ocserv.conf', 'oc');
            if ($this->sshRun('sleep 1; pgrep ocserv > /dev/null', 'oc')['rc'] === 1 && is_file('/certs/cert_public')) {
                // it does not start with the new config: the previous one back
                if ($this->rollbackConfig(BOT_DATA . '/ocserv/ocserv.conf')) {
                    $this->ssh('ocserv -c /etc/ocserv/ocserv.conf', 'oc');
                }
                $this->configRejected('ocserv.conf', 'ocserv did not start with the new config, the previous one is back');
                return false;
            }
        }
        return true;
    }


    public function chOcSubdomain($domain)
    {
        $pac = $this->getPacConf();
        // a DNS label: it goes into the nginx SNI map, ocserv.conf and the certificate
        $domain = strtolower(trim((string) $domain));
        if ($domain !== '-1' && !preg_match('~^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$~D', $domain)) {
            $this->send($this->input['chat'], 'wrong subdomain: a-z, 0-9, -');
            return $this->menu('oc');
        }
        if ($domain === '-1') {
            unset($pac["oc_domain"]);
        } else {
            $pac["oc_domain"] = $domain;
        }
        $this->setPacConf($pac);
        $this->chocdomain($pac['domain']);
        $this->setUpstreamDomainOcserv($pac['domain']);
        // the OpenConnect name is in the certificate: a new one with it
        if (($pac['letsencrypt'] ?? '') === 'letsencrypt' && !empty($pac['domain'])) {
            $this->certTask(false);
            $this->send($this->input['chat'], 'the certificate is renewed for the new name: a message follows');
        }
        $this->menu('oc');
    }

    public function chockey($pass)
    {
        // a quoted value in ocserv.conf and a query string in the client link
        if (!preg_match('#^[A-Za-z0-9._~-]{1,64}$#D', $pass = trim((string) $pass))) {
            $this->send($this->input['chat'], 'wrong secret: 1-64 characters A-Z a-z 0-9 . _ ~ -');
            return $this->menu('oc');
        }
        $c = bot_read(BOT_DATA . '/ocserv/ocserv.conf');
        $t = preg_replace('~^camouflage_secret[^\n]+~sm', "camouflage_secret = \"$pass\"", $c);
        if ($this->restartOcserv($t)) {
            $this->setSecret('oc_camouflage', $pass);
        }
        $this->menu('oc');
    }

    public function chocdomain($domain)
    {
        if ($domain && !$this->validHost($domain)) {
            return;
        }
        $oc = $this->getHashSubdomain('oc');
        $c  = bot_read(BOT_DATA . '/ocserv/ocserv.conf');
        $t  = preg_replace('~^default-domain[^\n]+~sm', "default-domain = $oc.$domain", $c);
        $this->restartOcserv($t);
    }

    public function chocpass($pass)
    {
        // one password for every user: long enough not to be guessed
        if (!$this->validSecret($pass = trim((string) $pass), 12)) {
            $this->send($this->input['chat'], 'wrong password: 12-128 printable characters, no ":"');
            return;
        }
        $this->setSecret('ocserv', $pass);
        $this->ocPasswd(array_fill_keys($this->getClientsOc(), $pass));
        $this->restartOcserv(bot_read(BOT_DATA . '/ocserv/ocserv.conf'));
        $this->menu('oc');
    }

    public function ocMenu()
    {
        $pac    = $this->getPacConf();
        $domain = $this->getDomain();
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('ocserv');
        // the login link (with the camouflage secret) and the password: in
        // the Mini App (secrets), here only masked
        $oc     = $this->getHashSubdomain('oc');
        $text[] = "https://$oc.$domain/?" . $this->mask($this->secret('oc_camouflage'));
        $text[] = 'password: ' . $this->mask($this->secret('ocserv'));
        [$down, $up] = $this->ocUserTraffic(null);
        $text[] = '↓' . $this->getBytes($down) . '  ↑' . $this->getBytes($up);
        $data[] = [
            [
                'text'          => $this->i18n('reset stats'),
                'callback_data' => '/resetOcStats',
            ],
            [
                // one switch with Xray (checkResetXrayStats)
                'text'          => $this->i18n('reset monthly') . ': ' . $this->i18n(!empty($pac['reset_monthly']) ? 'on' : 'off'),
                'callback_data' => '/switchMonthlyStats oc',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('change subdomain'),
                'callback_data' => "/changeOcDomain",
            ],
            [
                'text'          => $this->i18n('change secret'),
                'callback_data' => "/changeCamouflage",
            ],
            [
                'text'          => $this->i18n('change password'),
                'callback_data' => "/changeOcPass",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('add peer'),
                'callback_data' => "/addOcUser",
            ],
            $this->secretsButton('ocserv'),
        ];
        $clients = $this->getClientsOc();
        foreach ($clients as $k => $v) {
            $data[] = [
                [
                    'text'          => $v,
                    'callback_data' => '/ocUser ' . $this->shortId($v),
                ],
                [
                    'text'          => $this->i18n('delete'),
                    'callback_data' => '/deloc ' . $this->shortId($v),
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => implode("\n", $text),
            'data' => $data,
        ];
    }


    /*
     * OpenConnect traffic, per user (data/octraffic.json):
     *   users:  name => [in, out]   counted so far (in: from the client)
     *   seen:   session id => user, in, out (the tun device's counters at
     *           the last look) and base_in, base_out (what of them is
     *           counted already, or was before a reset)
     *   folded: sessions gone before their final count came: what of
     *           them is counted, to add only the rest when it comes
     * Once a minute (cron) the open sessions are read from occtl and their
     * tun devices; when a session ends, ocserv's disconnect script leaves
     * its exact count in data/octraffic (scripts/oc_disconnect.sh). Without
     * it (ocserv stopped) the last look is what counts.
     */
    public function ocTrafficFile(): string
    {
        return BOT_DATA . '/octraffic.json';
    }

    public function ocTrafficState(): array
    {
        $f = $this->ocTrafficFile();
        $s = is_file($f) ? bot_read_json($f) : [];
        return $s + ['users' => [], 'seen' => [], 'folded' => []];
    }

    public function updateOcTraffic(callable $fn): array
    {
        return bot_update_json($this->ocTrafficFile(), function ($s) use ($fn) {
            return $fn($s + ['users' => [], 'seen' => [], 'folded' => []]);
        }, 0600, null, true);
    }

    // [download, upload] of a user, or of all with null; open sessions included
    public function ocUserTraffic(?string $name): array
    {
        $s    = $this->ocTrafficState();
        $down = $up = 0;
        foreach ($s['users'] as $u => $t) {
            if ($name === null || (string) $u === $name) {
                $down += (int) ($t['out'] ?? 0);
                $up   += (int) ($t['in'] ?? 0);
            }
        }
        foreach ($s['seen'] as $t) {
            if ($name === null || (string) ($t['user'] ?? '') === $name) {
                $down += max(0, (int) $t['out'] - (int) $t['base_out']);
                $up   += max(0, (int) $t['in'] - (int) $t['base_in']);
            }
        }
        return [$down, $up];
    }

    // cron, once a minute: the open sessions and the ended ones
    public function ocTraffic()
    {
        if (!empty($this->time_oc_traffic) && time() - $this->time_oc_traffic < 60) {
            return;
        }
        $this->time_oc_traffic = time();

        // the open sessions: occtl and the counters of their tun devices
        $r    = $this->sshRun('occtl --json show users 2> /dev/null; echo __dev; for d in /sys/class/net/vpns*; do [ -d "$d" ] && echo "${d##*/} $(cat "$d/statistics/rx_bytes") $(cat "$d/statistics/tx_bytes")"; done; true', 'oc');
        $list = null;
        $devs = [];
        if ($r['rc'] === 0 && str_contains($r['out'], '__dev')) {
            [$json, $dev] = explode('__dev', $r['out'], 2);
            // no JSON (occtl does not reach ocserv): the sessions are left as they were
            $list = trim($json) === '' ? null : json_decode($json, true);
            foreach (explode("\n", $dev) as $l) {
                if (preg_match('~^(\S+) (\d+) (\d+)$~', trim($l), $m)) {
                    // rx: what the client sent (ocserv writes it to the device)
                    $devs[$m[1]] = [(int) $m[2], (int) $m[3]];
                }
            }
        }
        $dir   = BOT_DATA . '/octraffic';
        $files = array_filter(glob("$dir/*-*") ?: [], fn ($f) => !str_ends_with($f, '.tmp'));
        $users = $this->getClientsOc();
        $this->updateOcTraffic(function ($s) use ($files, $list, $devs, $users) {
            $add = function ($user, $in, $out) use (&$s) {
                $s['users'][$user]['in']  = (int) ($s['users'][$user]['in'] ?? 0) + max(0, (int) $in);
                $s['users'][$user]['out'] = (int) ($s['users'][$user]['out'] ?? 0) + max(0, (int) $out);
            };
            $done = [];
            foreach ($files as $f) {
                $id = substr(basename($f), strpos(basename($f), '-') + 1);
                $l  = explode("\n", (string) @file_get_contents($f));
                if (count($l) < 3) {
                    continue;
                }
                // the base and the name (renamed meanwhile) from the session as seen
                $b    = $s['seen'][$id] ?? $s['folded'][$id] ?? null;
                $user = (string) ($b['user'] ?? trim($l[0]));
                $add($user, (int) $l[1] - (int) ($b['base_in'] ?? $b['in'] ?? 0), (int) $l[2] - (int) ($b['base_out'] ?? $b['out'] ?? 0));
                unset($s['seen'][$id], $s['folded'][$id]);
                $done[$id] = true;
            }
            if (is_array($list)) {
                $now = [];
                foreach ($list as $u) {
                    $id  = (string) ($u['ID'] ?? '');
                    $dev = (string) ($u['Device'] ?? '');
                    if ($id === '' || isset($done[$id]) || !isset($devs[$dev])) {
                        continue;
                    }
                    [$in, $out] = $devs[$dev];
                    $old = $s['seen'][$id] ?? null;
                    if ($old !== null && $in < (int) $old['in']) {
                        // another session on this id: the old one ends here
                        $add($old['user'], $old['in'] - $old['base_in'], $old['out'] - $old['base_out']);
                        $old = null;
                    }
                    if ($old === null && isset($s['folded'][$id])) {
                        // back after a look without occtl: counted up to there
                        $f   = $s['folded'][$id];
                        $old = ['user' => $f['user'], 'base_in' => $f['in'], 'base_out' => $f['out']];
                        unset($s['folded'][$id]);
                    }
                    $now[$id] = [
                        'user'     => (string) ($old['user'] ?? $u['Username'] ?? ''),
                        'in'       => $in,
                        'out'      => $out,
                        'base_in'  => (int) ($old['base_in'] ?? 0),
                        'base_out' => (int) ($old['base_out'] ?? 0),
                    ];
                }
                // gone without a final count (yet): counted as last seen
                foreach ($s['seen'] as $id => $t) {
                    if (!isset($now[$id])) {
                        $add($t['user'], $t['in'] - $t['base_in'], $t['out'] - $t['base_out']);
                        $s['folded'][$id] = ['user' => $t['user'], 'in' => $t['in'], 'out' => $t['out'], 'time' => time()];
                    }
                }
                $s['seen'] = $now;
            }
            // a final count a day late is not coming
            $s['folded'] = array_filter($s['folded'], fn ($f) => time() - (int) ($f['time'] ?? 0) < 86400);
            // deleted users
            $s['users'] = array_intersect_key($s['users'], array_flip($users));
            return $s;
        });
        foreach ($files as $f) {
            @unlink($f);
        }
    }

    // the traffic of a renamed user goes with the name
    public function ocTrafficRename(string $old, string $new)
    {
        $this->updateOcTraffic(function ($s) use ($old, $new) {
            if (isset($s['users'][$old])) {
                $s['users'][$new] = $s['users'][$old];
                unset($s['users'][$old]);
            }
            foreach (['seen', 'folded'] as $k) {
                foreach ($s[$k] as $id => $t) {
                    if (($t['user'] ?? '') === $old) {
                        $s[$k][$id]['user'] = $new;
                    }
                }
            }
            return $s;
        });
    }

    // the traffic counted from zero: of all users, or of one (shortId of the name)
    public function resetOcStats(?string $id = null, $nomenu = false)
    {
        $name = $id !== null ? $this->ocName($id) : null;
        if ($id !== null && $name === null) {
            return $this->menu('oc');
        }
        $this->updateOcTraffic(function ($s) use ($name) {
            foreach ($s['users'] as $u => $t) {
                if ($name === null || (string) $u === $name) {
                    unset($s['users'][$u]);
                }
            }
            // open sessions: from their current counters on
            foreach ($s['seen'] as $sid => $t) {
                if ($name === null || $t['user'] === $name) {
                    $s['seen'][$sid]['base_in']  = $t['in'];
                    $s['seen'][$sid]['base_out'] = $t['out'];
                }
            }
            return $s;
        });
        if ($nomenu) {
            return;
        }
        return $name !== null ? $this->ocUser($id) : $this->menu('oc');
    }

    // the OpenConnect user with this shortId() of the name, null if gone
    public function ocName(string $id): ?string
    {
        foreach ($this->getClientsOc() as $v) {
            if ($id === $this->shortId($v)) {
                return $v;
            }
        }
        return null;
    }

    public function ocUser(string $id)
    {
        if (($name = $this->ocName($id)) === null) {
            return $this->menu('oc');
        }
        [$down, $up] = $this->ocUserTraffic($name);
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $this->i18n('Menu') . ' -> ' . $this->i18n('ocserv') . ' -> ' . htmlspecialchars($name)
                . "\n↓" . $this->getBytes($down) . '  ↑' . $this->getBytes($up),
            [
                [
                    [
                        'text'          => $this->i18n('rename'),
                        'callback_data' => "/renameOcUser $id",
                    ],
                    [
                        'text'          => $this->i18n('reset stats'),
                        'callback_data' => "/resetOcStats $id",
                    ],
                ],
                [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => '/menu oc',
                    ],
                ],
            ],
        );
    }

    public function renameOcUser(string $i)
    {
        $this->prompt($this->i18n('enter name'), $this->i18n('enter name'), 'renOcUs', [$i]);
    }

    // all OpenConnect users share one password: the new name gets it, the old one is removed
    public function renOcUs($name, $i)
    {
        if (($old = $this->ocName((string) $i)) === null) {
            return $this->menu('oc');
        }
        $clients = $this->getClientsOc();
        if (!preg_match('~^[A-Za-z0-9._@-]{1,64}$~D', $name = trim((string) $name))) {
            $this->send($this->input['chat'], 'wrong name: A-Z a-z 0-9 . _ @ -');
            return $this->ocUser($i);
        }
        if ($name === $old) {
            return $this->ocUser($i);
        }
        if (in_array($name, $clients, true)) {
            $this->send($this->input['chat'], "user $name already exists");
            return $this->ocUser($i);
        }
        if (($pass = $this->secret('ocserv')) === '') {
            $this->send($this->input['chat'], 'set the OpenConnect password first');
            return $this->ocUser($i);
        }
        $this->ocPasswd([$name => $pass], [$old]);
        $this->ocTrafficRename($old, $name);
        return $this->ocUser($this->shortId($name));
    }

    public function deloc($id)
    {
        if (($name = $this->ocName((string) $id)) !== null) {
            $this->ocPasswd([], [$name]);
        }
        $this->menu('oc');
    }

    /**
     * ocserv.passwd ("user:group:hash" lines), written here and not by
     * ocpasswd in the oc container, which gets its configs read-only. The
     * hash is SHA-256 crypt, as ocpasswd makes it. ocserv reads the file on
     * every login. $set: user => password, $delete: users.
     */
    public function ocPasswd(array $set = [], array $delete = [])
    {
        $f = BOT_DATA . '/ocserv/ocserv.passwd';
        bot_lock($f, function () use ($f, $set, $delete) {
            $lines = [];
            foreach (explode("\n", bot_read($f)) as $l) {
                if (($l = trim($l)) !== '') {
                    $lines[explode(':', $l)[0]] = $l;
                }
            }
            foreach ($delete as $u) {
                unset($lines[$u]);
            }
            foreach ($set as $u => $p) {
                $group = explode(':', $lines[$u] ?? '')[1] ?? '*';
                $salt  = strtr(substr(base64_encode(random_bytes(12)), 0, 16), '+', '.');
                $lines[$u] = "$u:" . ($group !== '' ? $group : '*') . ':' . crypt((string) $p, '$5$' . $salt . '$');
            }
            bot_write($f, $lines ? implode("\n", $lines) . "\n" : '');
        });
    }

    public function getClientsOc()
    {
        $users = array_filter(explode("\n", bot_read(BOT_DATA . '/ocserv/ocserv.passwd')), fn ($e) => !empty($e));
        return array_map(fn($e) => explode(':', $e)[0], $users);
    }

    public function addocus($user)
    {
        // ocserv.passwd is "user:hash" lines
        if (!preg_match('~^[A-Za-z0-9._@-]{1,64}$~D', $user = trim((string) $user))) {
            $this->send($this->input['chat'], 'wrong name: A-Z a-z 0-9 . _ @ -');
            return;
        }
        if (($pass = $this->secret('ocserv')) === '') {
            // a user without the shared password could log in with an empty one
            $this->send($this->input['chat'], 'set the OpenConnect password first');
            return $this->menu('oc');
        }
        $this->ocPasswd([$user => $pass]);
        $this->menu('oc');
    }

    public function setUpstreamDomainOcserv($domain)
    {
        if ($domain && !$this->validHost($domain)) {
            return;
        }
        $sub   = $this->getHashSubdomain('oc');
        $nginx = bot_read(BOT_DATA . '/up/upstream.conf');
        $t     = preg_replace('~#ocserv.+#ocserv~s', $domain ? "#ocserv\n" . ($sub ? '' : '#' ) . "$sub.$domain ocserv;\n#ocserv" : "#ocserv\n#$sub.\$domain ocserv;\n#ocserv", $this->upstreamConf($nginx));
        $this->applyUpstream($t);
    }
}
