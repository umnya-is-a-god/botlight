<?php

// Xray: config, users, traffic, IP limit: methods of class Bot (app/bot.php)
trait BotXray
{
    // the parts of the Xray config the bot relies on: API, stats, policy, rules order
    public function xrayNormalize(array $c): array
    {
        $c['inbounds'][0]['settings']['clients'] = array_values($c['inbounds'][0]['settings']['clients']);
        // Xray's access log lists every site each user opens: kept only while
        // the IP limit needs it (it is read to count IPs per user). Error log
        // at warning: "info" also prints every destination.
        $c['log']['access']   = empty($this->getPacConf()['ip_limit']) ? 'none' : '/logs/xray';
        $c['log']['loglevel'] = 'warning';
        foreach ($c['inbounds'] as $v) {
            if (($v['tag'] ?? null) == 'api') {
                $api = true;
                break;
            }
        }
        if (empty($api)) {
            $c['inbounds'][] = [
                "listen"   => "127.0.0.1",
                "port"     => 8080,
                "protocol" => "dokodemo-door",
                "settings" => [
                    "address" => "127.0.0.1"
                ],
                "tag" => "api"
            ];
        }
        foreach ($c['routing']['rules'] as $v) {
            if (($v['outboundTag'] ?? null) == 'api') {
                $rule = true;
                break;
            }
        }
        if (empty($rule)) {
            $c['routing']['rules'][] = [
                "inboundTag"  => ["api"],
                "outboundTag" => "api",
                "type"        => "field"
            ];
        }

        // the unauthenticated socks inbound for the removed WireGuard containers
        $c['inbounds'] = array_values(array_filter($c['inbounds'], fn($e) => ($e['tag'] ?? '') != 'wg-in'));

        // clients must not reach the server's internal networks (containers,
        // php-fpm, sshd, xray api) or the host: keep the api rule first,
        // then block private destinations, then the user rules
        $private = [
            'ruleTag'     => 'private-block',
            'type'        => 'field',
            'outboundTag' => 'block',
            'ip'          => [
                '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
                '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10',
            ],
        ];
        $rules = $c['routing']['rules'] ?? [];
        $api   = array_filter($rules, fn($e) => ($e['outboundTag'] ?? '') == 'api');
        $other = array_filter($rules, fn($e) => ($e['outboundTag'] ?? '') != 'api' && ($e['ruleTag'] ?? '') != 'private-block');
        $c['routing']['rules'] = array_values(array_merge($api, [$private], $other));
        $c['stats'] = new stdClass();
        // HandlerService: users are added and removed without a restart
        $c['api'] = [
            'services' => ['StatsService', 'HandlerService'],
            'tag'      => 'api'
        ];
        $l = new stdClass();
        $l->{'0'} = [
            "statsUserUplink"   => true,
            "statsUserDownlink" => true
        ];
        $c['policy']['levels'] = $l;
        $c['policy']['system'] = [
            "statsInboundUplink"    => true,
            "statsInboundDownlink"  => true,
            "statsOutboundUplink"   => true,
            "statsOutboundDownlink" => true
        ];
        return $c;
    }

    public function restartXray($c, $norestart = false, $rename = null)
    {
        $c = $this->xrayNormalize($c);
        $json = json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (empty($norestart)) {
            // Xray's counters start from zero after the restart. In one locked
            // step (the cron loop updates the same stats): latest counters
            // under the running config's names, into the totals, the renamed
            // user's record to the new name, new config, restart.
            $ok = true;
            $this->updateXrayStats(function ($p) use ($c, $rename, $json, &$ok) {
                $running = array_map(fn($e) => (string) ($e['email'] ?? ''), $this->getXray()['inbounds'][0]['settings']['clients'] ?? []);
                // only a config Xray accepts; else nothing changes
                if (!$this->applyConfig(BOT_DATA . '/xray/xray.json', $json, 'xr', self::XRAY_TEST)) {
                    $ok = false;
                    return $p;
                }
                $this->saveXrayView($c);
                if (($cnt = $this->xrayCounters()) !== null) {
                    // Xray may have restarted since the last read (the bot
                    // runs this on every start): its earlier counts first
                    $p = $this->foldIfXrayRestarted($p, $cnt);
                    $p = $this->applyCounters($p, $cnt, $running);
                }
                $p = $this->sessionToGlobal($p);
                unset($p['xray_uptime']);
                if ($rename && isset($p['users'][$rename[0]])) {
                    $p['users'][$rename[1]] = $p['users'][$rename[0]];
                    unset($p['users'][$rename[0]]);
                }
                // users no longer in the config (deleted) leave the stats
                $emails     = array_map(fn($e) => (string) ($e['email'] ?? ''), $c['inbounds'][0]['settings']['clients'] ?? []);
                $p['users'] = array_intersect_key($p['users'] ?? [], array_flip($emails));
                $this->startXray();
                if (!$this->xrayRunning()) {
                    // accepted by the test, but Xray does not run with it:
                    // the previous config back
                    if ($this->rollbackConfig(BOT_DATA . '/xray/xray.json')) {
                        $this->saveXrayView($this->getXray());
                        $this->startXray();
                    }
                    $this->configRejected('xray.json', 'Xray stopped with the new config, the previous one is back: ' . $this->ssh('tail -n 20 /logs/xray_error', 'xr'));
                    $ok = false;
                }
                return $p;
            });
            return $ok;
        }
        if ($this->applyConfig(BOT_DATA . '/xray/xray.json', $json, 'xr', self::XRAY_TEST)) {
            $this->saveXrayView($c);
            return true;
        }
        return false;
    }

    /**
     * A change of the user list without restarting Xray: users that went or
     * changed (id) are removed and the new or changed ones added through
     * Xray's API (HandlerService); the config file gets the same list (after
     * the test). Anything else changed, or the API failing: restartXray.
     * $rename: [old name, new name] (its traffic record moves along).
     */
    public function xrayApplyUsers(array $c, ?array $rename = null): bool
    {
        $c   = $this->xrayNormalize($c);
        $old = $this->xrayNormalize($this->getXray());
        $a   = $old;
        $b   = $c;
        unset($a['inbounds'][0]['settings']['clients'], $b['inbounds'][0]['settings']['clients']);
        if ($a != $b) {
            return $this->restartXray($c, false, $rename);
        }
        $by  = fn($cfg) => array_column(array_map(fn($e) => ['email' => (string) ($e['email'] ?? ''), 'c' => array_intersect_key($e, array_flip(['id', 'email', 'flow']))], $cfg['inbounds'][0]['settings']['clients']), 'c', 'email');
        $was = $by($old);
        $now = $by($c);
        $rm  = array_keys(array_filter($was, fn($v, $k) => !isset($now[$k]) || $now[$k] != $v, ARRAY_FILTER_USE_BOTH));
        $add = array_values(array_filter($now, fn($v, $k) => !isset($was[$k]) || $was[$k] != $v, ARRAY_FILTER_USE_BOTH));
        $json = json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $ok   = true;
        $api  = true;
        $this->updateXrayStats(function ($p) use ($c, $json, $rename, $rm, $add, $was, &$ok, &$api) {
            if (!$this->applyConfig(BOT_DATA . '/xray/xray.json', $json, 'xr', self::XRAY_TEST)) {
                $ok = false;
                return $p;
            }
            $this->saveXrayView($c);
            if (($cnt = $this->xrayCounters()) === null) {
                // Xray does not answer: it gets the file on its next start
                return $p;
            }
            $p    = $this->applyCounters($this->foldIfXrayRestarted($p, $cnt), $cnt, array_keys($was));
            $tag  = $c['inbounds'][0]['tag'] ?? 'vless_tls';
            $gone = array_diff($rm, array_column($add, 'email'));
            if ($rm) {
                $out = $this->ssh('xray api rmu --server=127.0.0.1:8080 -tag=' . escapeshellarg($tag) . ' ' . implode(' ', array_map('escapeshellarg', $rm)) . ' 2>&1', 'xr');
                $api = $api && preg_match('~Removed (\d+) user~', $out, $m) && (int) $m[1] === count($rm);
            }
            if ($add && $api) {
                $in  = json_encode(['inbounds' => [[
                    'tag'      => $tag,
                    'port'     => $c['inbounds'][0]['port'] ?? 443,
                    'protocol' => 'vless',
                    'settings' => ['clients' => $add, 'decryption' => 'none'],
                ]]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $out = $this->ssh('printf %s ' . escapeshellarg($in) . ' | xray api adu --server=127.0.0.1:8080 stdin: 2>&1', 'xr');
                $api = preg_match('~Added (\d+) user~', $out, $m) && (int) $m[1] === count($add);
            }
            if (!$api) {
                return $p;
            }
            // traffic: by name; a renamed user's record moves (its new name
            // counts from zero), a deleted one's goes
            if ($rename && isset($p['users'][$rename[0]])) {
                $u = $p['users'][$rename[0]];
                $u['global'] = [
                    'download' => ($u['global']['download'] ?? 0) + ($u['session']['download'] ?? 0),
                    'upload'   => ($u['global']['upload'] ?? 0) + ($u['session']['upload'] ?? 0),
                ];
                $u['session'] = ['download' => 0, 'upload' => 0];
                $p['users'][$rename[1]] = $u;
                $gone[] = $rename[0];
            }
            foreach (array_unique(array_merge($gone, $rename ? [$rename[1]] : [])) as $e) {
                // counters of a name stay in Xray: zero them for a later user of that name
                foreach (['downlink', 'uplink'] as $d) {
                    $this->ssh('xray api stats --server=127.0.0.1:8080 -reset -name ' . escapeshellarg("user>>>$e>>>traffic>>>$d") . ' >/dev/null 2>&1', 'xr');
                }
            }
            $p['users'] = array_diff_key($p['users'] ?? [], array_flip(array_diff($gone, $rename ? [$rename[1]] : [])));
            return $p;
        });
        if ($ok && !$api) {
            // no API (an Xray from before HandlerService) or it failed: restart
            return $this->restartXray($c, false, $rename);
        }
        return $ok;
    }

    // Xray started again; its errors go to /logs/xray_error
    public function startXray()
    {
        $this->ssh('pkill xray', 'xr');
        // not without the egress filter (see scripts/start_xray.sh)
        $this->ssh('[ -e /tmp/fw_failed ] || xray run -config /xray/xray.json >> /logs/xray_error 2>&1 &', 'xr');
    }

    // Xray runs (or is off on purpose: no egress filter, see start_xray.sh)
    public function xrayRunning(): bool
    {
        $r = $this->sshRun('[ -e /tmp/fw_failed ] && exit 0; sleep 1; pgrep -x xray > /dev/null', 'xr');
        // not reachable: nothing known, nothing to undo
        return $r['rc'] === null || $r['rc'] === 0;
    }

    public function addXrUser()
    {
        $this->prompt($this->i18n('enter name'), $this->i18n('enter name:uuid [,name:uuid]'), 'addxrus');
    }

    // $uid: the user's id (renXrUs finds the user again by it)
    public function renameXrUser($uid)
    {
        $this->prompt($this->i18n('enter name'), $this->i18n('enter name'), 'renXrUs', [$uid]);
    }

    /**
     * Traffic counters of the running Xray, one query for all of them.
     * Users are keyed by name (the counter name in Xray), not by position in
     * the client list: deleting a user must not shift the others' traffic.
     * session = counters since Xray started; global = earlier sessions.
     */
    public function xrayStatsUser($force = false)
    {
        if (!$force && !empty($this->time_xray_stats) && time() - $this->time_xray_stats <= 60) {
            return;
        }
        $this->time_xray_stats = time();
        try {
            // counters and names read under the lock: a restart in between
            // would make them stale (already moved into the totals)
            $this->updateXrayStats(function ($p) {
                if (($cnt = $this->xrayCounters()) === null) {
                    return $p; // Xray not running: keep the last values
                }
                $p = $this->foldIfXrayRestarted($p, $cnt);
                $emails = array_map(fn($e) => (string) ($e['email'] ?? ''), $this->getXray()['inbounds'][0]['settings']['clients'] ?? []);
                return $this->applyCounters($p, $cnt, $emails);
            });
        } catch (\Throwable $th) {
        }
    }

    /*
     * Xray restarted outside the bot (restart or rebuild button, make r,
     * reboot, update, crash): its counters began again from zero, so what it
     * had counted before moves into the totals first. Told by its uptime or
     * any of its counters going down (not by the clock, which may jump): a
     * running Xray only counts up. Called before the stats take Xray's
     * current counters.
     */
    public function foldIfXrayRestarted(array $p, array $cnt): array
    {
        $uptime    = $this->xrayUptime();
        $restarted = $uptime !== null && isset($p['xray_uptime']) && $uptime < (int) $p['xray_uptime'];
        $was       = ['' => $p['session'] ?? []];
        foreach ($p['users'] ?? [] as $e => $v) {
            $was[(string) $e] = $v['session'] ?? [];
        }
        foreach ($was as $e => $session) {
            foreach (['download' => 'downlink', 'upload' => 'uplink'] as $k => $dir) {
                $name = $e === '' ? "inbound>>>vless_tls>>>traffic>>>$dir" : "user>>>$e>>>traffic>>>$dir";
                if (($cnt[$name] ?? 0) < (int) ($session[$k] ?? 0)) {
                    $restarted = true;
                }
            }
        }
        if ($restarted) {
            $p = $this->sessionToGlobal($p);
        }
        if ($uptime !== null) {
            $p['xray_uptime'] = $uptime;
        }
        return $p;
    }

    // seconds the running Xray has been up, null when it does not answer
    public function xrayUptime(): ?int
    {
        $out = json_decode((string) $this->ssh('xray api statssys --server=127.0.0.1:8080 2>/dev/null', 'xr'), true);
        return isset($out['Uptime']) ? (int) $out['Uptime'] : null;
    }

    // all counters of the running Xray by name, null when it does not answer
    public function xrayCounters(): ?array
    {
        $out = json_decode($this->ssh('xray api statsquery --server=127.0.0.1:8080 -pattern "" 2>/dev/null', 'xr'), true);
        if (!is_array($out)) {
            return null;
        }
        $cnt = [];
        foreach ($out['stat'] ?? [] as $v) {
            // a counter with value 0 comes without "value"
            $cnt[$v['name'] ?? ''] = (int) ($v['value'] ?? 0);
        }
        return $cnt;
    }

    // counters into the stats record: session = what Xray counted since start
    public function applyCounters(array $p, array $cnt, array $emails): array
    {
        $p['session'] = [
            'download' => $cnt['inbound>>>vless_tls>>>traffic>>>downlink'] ?? 0,
            'upload'   => $cnt['inbound>>>vless_tls>>>traffic>>>uplink'] ?? 0,
        ];
        foreach ($emails as $e) {
            $p['users'][$e]['session'] = [
                'download' => $cnt["user>>>$e>>>traffic>>>downlink"] ?? 0,
                'upload'   => $cnt["user>>>$e>>>traffic>>>uplink"] ?? 0,
            ];
            $p['users'][$e]['global'] ??= ['download' => 0, 'upload' => 0];
        }
        return $p;
    }

    // session into global for everyone (right before Xray restarts)
    public function sessionToGlobal(array $p): array
    {
        $p['global'] = [
            'download' => ($p['global']['download'] ?? 0) + ($p['session']['download'] ?? 0),
            'upload'   => ($p['global']['upload'] ?? 0) + ($p['session']['upload'] ?? 0),
        ];
        $p['session'] = ['download' => 0, 'upload' => 0];
        foreach ($p['users'] ?? [] as $k => $v) {
            $p['users'][$k]['global']['download'] = ($v['global']['download'] ?? 0) + ($v['session']['download'] ?? 0);
            $p['users'][$k]['global']['upload']   = ($v['global']['upload'] ?? 0) + ($v['session']['upload'] ?? 0);
            $p['users'][$k]['session']            = ['download' => 0, 'upload' => 0];
        }
        return $p;
    }

    /**
     * Read-modify-write of xray.stats under a lock: the bot (php) and the
     * cron loop (service) both update it.
     */
    public function updateXrayStats(callable $fn)
    {
        bot_lock(BOT_DATA . '/xray.stats', function () use ($fn) {
            $this->setXrayStats($fn($this->getXrayStats()));
        });
    }

    // traffic of client $c (from the Xray config): [download, upload]
    public function userTraffic(array $st, $c): array
    {
        $u = $st['users'][(string) ($c['email'] ?? '')] ?? [];
        return [
            ($u['global']['download'] ?? 0) + ($u['session']['download'] ?? 0),
            ($u['global']['upload'] ?? 0) + ($u['session']['upload'] ?? 0),
        ];
    }

    /**
     * Monthly reset of the Xray and OpenConnect traffic: on the first run of each calendar
     * month (server time zone). Turned on in the middle of a month, the
     * first reset is at the start of the next one.
     */
    public function checkResetXrayStats()
    {
        $pac = $this->getPacConf();
        if (empty($pac['reset_monthly'])) {
            return;
        }
        $month = date('Y-m');
        $reset = false;
        $this->updateState(function ($st) use ($pac, $month, &$reset) {
            // earlier versions: the time of the last reset in the settings
            $last = $st['last_reset_month'] ?? (!empty($pac['last_reset_xray_time']) ? date('Y-m', (int) $pac['last_reset_xray_time']) : $month);
            $reset = $last !== $month;
            $st['last_reset_month'] = $month;
            return $st;
        });
        if ($reset) {
            $this->resetXrStats(1);
            $this->resetOcStats(null, true);
            foreach ($this->config()['admin'] ?? [] as $admin) {
                $this->send($admin, "vless, openconnect: reset stats");
            }
        }
    }


    public function qrXray($i, $s = false)
    {
        $link    = $this->linkXray($i, $s);
        // /app is read-only; a name of its own for each picture
        $qr_file = tempnam(sys_get_temp_dir(), 'qr');
        exec('qrencode -t png -o ' . escapeshellarg($qr_file) . ' ' . escapeshellarg($link));
        $r = $this->sendPhoto(
            $this->input['chat'],
            curl_file_create($qr_file, 'image/png', 'qr.png'),
            "<code>$link</code>"
        );
        @unlink($qr_file);
    }

    public function setIpLimit()
    {
        $this->prompt($this->i18n('enter seconds and count ip'), $this->i18n('enter seconds:count_ip'), 'switchIpLimit');
    }

    public function xrayUpdateRules()
    {
        $c  = $this->getPacConf();
        $xr = $this->getXray();
        $xr['outbounds'] = [
            [
                "protocol" => "freedom",
                "tag"      => "direct",
            ],
            [
                "protocol" => "blackhole",
                "tag"      => "block",
            ],
            [
                "protocol" => "socks",
                "tag"      => "warp",
                "settings" => [
                    'servers' => [
                        [
                            "address" => "10.10.0.13",
                            "port"    => 1080,
                        ],
                    ],
                ],
            ],
        ];
        // entries switched on: addresses (IPv4/IPv6, CIDR) go to "ip", names to "domain"
        $rules = [];
        foreach (['blocklist' => 'block', 'warplist' => 'warp'] as $list => $tag) {
            $on      = array_map('strval', array_keys(array_filter($c[$list] ?? [])));
            $ips     = array_values(array_filter($on, [$this, 'validIpOrCidr']));
            $domains = array_values(array_diff($on, $ips));
            foreach (['domain' => $domains, 'ip' => $ips] as $field => $v) {
                if ($v) {
                    $rules[] = [
                        "type"        => "field",
                        "outboundTag" => $tag,
                        $field        => $v,
                    ];
                }
            }
        }
        $xr['routing']['rules'] = $rules ?: [];
        $this->restartXray($xr);
    }

    // the monthly reset of Xray and OpenConnect traffic (Settings menu)
    public function switchMonthlyStats()
    {
        $c = $this->getPacConf();
        $c['reset_monthly'] = !empty($c['reset_monthly']) ? 0 : 1;
        unset($c['last_reset_xray_time']);
        if ($c['reset_monthly']) {
            // counted from this month: the first reset at the start of the next
            $this->updateState(function ($st) {
                $st['last_reset_month'] = date('Y-m');
                return $st;
            });
        }
        $this->setPacConf($c);
        $this->menu('config');
    }

    public function switchIpLimit($limit)
    {
        if (!empty($this->getPacConf()['bridge'])) {
            return $this->xray(); // bridge mode: no IP limit
        }
        $limit = explode(':', $limit);
        $c = $this->getPacConf();
        if ((int) $limit[0] <= 0) {
            unset($c['ip_limit']);
            unset($c['ip_count']);
        } else {
            $c['ip_limit'] = (int) $limit[0];
            $c['ip_count'] = (int) ($limit[1] ?? null) ?: 1;
        }
        $this->setPacConf($c);
        // the access log goes on/off with the limit
        $this->restartXray($this->getXray());
        if (empty($c['ip_limit'])) {
            @file_put_contents('/logs/xray', '');
        }
        $this->xray();
    }

    public function linkXray($i, $s = false)
    {
        $c      = $this->getXray();
        $pac    = $this->getPacConf();
        $domain = $this->getDomain(($pac['transport'] ?? null) != 'Reality');
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();
        $si     = $this->subLink($scheme, $domain, 'si', $c['inbounds'][0]['settings']['clients'][$i]['id']);

        switch ($s) {
            case 2:
                return "sing-box://import-remote-profile/?url={$si}#" . rawurlencode((string) $c['inbounds'][0]['settings']['clients'][$i]['email']);

            default:
                $rs = $c['inbounds'][0]['streamSettings']['realitySettings'] ?? [];
                switch ($pac['transport'] ?? '') {
                    case 'Reality':
                        $link = "vless://{$c['inbounds'][0]['settings']['clients'][$i]['id']}@$domain:443"
                                    . "?security=reality"
                                    . '&sni=' . ($rs['serverNames'][0] ?? '')
                                    . '&fp=chrome&pbk=' . ($pac['xray'] ?? '')
                                    . '&sid=' . ($rs['shortIds'][0] ?? '')
                                    . "&type=tcp"
                                    . "&flow=xtls-rprx-vision"
                                    . '#' . rawurlencode((string) $c['inbounds'][0]['settings']['clients'][$i]['email']);
                        break;
                    case 'xhttp':
                        $link = "vless://{$c['inbounds'][0]['settings']['clients'][$i]['id']}@$domain:443"
                                    . "?security=tls"
                                    . "&type=xhttp"
                                    . "&headerType="
                                    . "&path=%2Fws$hash"
                                    . "&host=$domain"
                                    . "&flow="
                                    . "&mode=packet-up"
                                    . "&extra=%7B%22xmux%22%3A%7B%22cMaxReuseTimes%22%3A0%2C%22maxConcurrency%22%3A%2216-32%22%2C%22maxConnections%22%3A0%2C%22hKeepAlivePeriod%22%3A0%2C%22hMaxRequestTimes%22%3A%22600-900%22%2C%22hMaxReusableSecs%22%3A%221800-3000%22%7D%2C%22headers%22%3A%7B%7D%2C%22noGRPCHeader%22%3Afalse%2C%22xPaddingBytes%22%3A%22100-1000%22%2C%22scMaxEachPostBytes%22%3A1000000%2C%22scMinPostsIntervalMs%22%3A30%2C%22scStreamUpServerSecs%22%3A%2220-80%22%7D"
                                    . "&sni=$domain"
                                    . "&fp=chrome"
                                    . "&alpn=h2"
                                    . '#' . rawurlencode((string) $c['inbounds'][0]['settings']['clients'][$i]['email']);
                        break;

                    default:
                        $link =  "vless://{$c['inbounds'][0]['settings']['clients'][$i]['id']}@$domain:443"
                                    . "?flow="
                                    . "&path=%2Fws$hash"
                                    . "&security=tls"
                                    . "&sni=$domain"
                                    . "&fp=chrome"
                                    . "&type=ws"
                                    . '#' . rawurlencode((string) $c['inbounds'][0]['settings']['clients'][$i]['email']);
                        break;
                }
                return $link;

        }
    }



    /**
     * Link of a sing-box/mihomo subscription or rule-set: the parameters in
     * the last path part (sing-box import links cannot carry a query) as
     * base64url JSON. Links of earlier versions (base64 of a PHP array)
     * are still read by index.php.
     */
    public function subLink(string $scheme, string $domain, string $type, string $uid, ?string $rule = null): string
    {
        $p = ['t' => $type, 's' => $uid];
        if ($rule !== null) {
            $p['r'] = $rule;
        }
        return "$scheme://$domain/pac{$this->getHashBot()}/" . rtrim(strtr(base64_encode(json_encode($p, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)), '+/', '-_'), '=');
    }

    // an Xray user's own id: the one in "off" while switched off
    public function xrUid(array $client): string
    {
        return (string) (($client['off'] ?? '') ?: ($client['id'] ?? ''));
    }

    // position of the user with this id in the client list, null if gone
    public function xrIndex(string $uid): ?int
    {
        foreach ($this->getXray()['inbounds'][0]['settings']['clients'] ?? [] as $k => $v) {
            if ($uid !== '' && hash_equals($this->xrUid($v), $uid)) {
                return (int) $k;
            }
        }
        return null;
    }

    // $fn with the user's position; a user deleted meanwhile: back to the list
    public function withXr(string $uid, callable $fn)
    {
        $i = $this->xrIndex($uid);
        if ($i === null) {
            $this->answer($this->input['callback_id'], 'no such user', true);
            return $this->xray();
        }
        return $fn($i);
    }

    public function delxr($i)
    {
        $r  = $this->getXray();
        foreach ($r['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($i == $k) {
                // its traffic record goes with it (xrayApplyUsers)
                unset($r['inbounds'][0]['settings']['clients'][$k]);
                $this->xrayApplyUsers($r);
                $this->adguardXrayClients();
                break;
            }
        }
        $this->xray();
    }

    public function addxrus($users)
    {
        $c     = $this->getXray();
        $p     = $this->getPacConf();
        $users = array_map(fn ($e) => trim($e), explode(',', $users));
        $users  = array_map(fn ($e) => explode(':', $e), $users);
        $uuids  = [];
        $emails = [];
        foreach ($c['inbounds'][0]['settings']['clients'] as $k => $v) {
            $uuids[]  = $v['id'];
            $emails[] = $v['email'];
        }
        foreach ($users as $user) {
            if (!$this->validName($user[0] ?? '') || (!empty($user[1]) && !preg_match('~^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$~iD', $user[1]))) {
                $this->send($this->input['chat'], 'wrong user: name[:uuid], name of letters, digits, emoji, space . _ @ -');
                return $this->xray();
            }
            $uuid = ($user[1] ?? '') ?: $this->uuid();
            if (in_array($uuid, $uuids ?: []) || in_array($user[0], $emails ?: [])) {
                $this->send($this->input['chat'], "user {$user[0]} already exists");
                return $this->xray();
            }
            $c['inbounds'][0]['settings']['clients'][] = ($p['transport'] ?? null) != 'Reality' ? [
                    'id'    => $uuid,
                    'email' => $user[0],
                ] : [
                    'id'    => $uuid,
                    'flow'  => 'xtls-rprx-vision',
                    'email' => $user[0],
            ];
        }
        $this->xrayApplyUsers($c);
        $this->adguardXrayClients();
        if (count($users) == 1) {
            $this->userXr(count($c['inbounds'][0]['settings']['clients']) - 1);
        } else {
            $this->xray();
        }
    }


    /**
     * A new subscription link: the user gets a new id, so the old vless link
     * and subscription stop working. Name, traffic, templates and on/off
     * stay (switched off: the new id waits in "off").
     */
    public function newSubXr($i, $yes = false)
    {
        $c   = $this->getXray();
        $cl  = $c['inbounds'][0]['settings']['clients'][$i];
        $uid = $this->xrUid($cl);
        if (empty($yes)) {
            return $this->update($this->input['chat'], $this->input['message_id'], $this->i18n('new subscription link') . ': ' . htmlspecialchars((string) $cl['email']) . "?\n\nThe current vless link and subscription of this user stop working; the user needs the new ones.", [
                [['text' => $this->i18n('yes'), 'callback_data' => "/newSubXr $uid yes"]],
                [['text' => $this->i18n('back'), 'callback_data' => "/userXr $uid"]],
            ]);
        }
        $new = $this->uuid();
        if (!empty($cl['off'])) {
            $c['inbounds'][0]['settings']['clients'][$i]['off'] = $new;
        } else {
            $c['inbounds'][0]['settings']['clients'][$i]['id'] = $new;
        }
        if (!$this->xrayApplyUsers($c)) {
            return $this->userXr($i);
        }
        $this->adguardXrayClients();
        $this->send($this->input['chat'], htmlspecialchars((string) $cl['email']) . ': new links below, the old ones no longer work');
        $this->userXr($i);
    }

    public function switchXr($i, $nm = 0)
    {
        $c = $this->getXray();
        if (empty($c['inbounds'][0]['settings']['clients'][$i]['off'])) {
            $c['inbounds'][0]['settings']['clients'][$i]['off'] = $c['inbounds'][0]['settings']['clients'][$i]['id'];
            $c['inbounds'][0]['settings']['clients'][$i]['id']  = $this->uuid();
        } else {
            $c['inbounds'][0]['settings']['clients'][$i]['id'] = $c['inbounds'][0]['settings']['clients'][$i]['off'];
            unset($c['inbounds'][0]['settings']['clients'][$i]['off']);
        }
        $this->xrayApplyUsers($c);
        // a user switched off gets no DNS either (allowed clients)
        $this->adguardXrayClients();
        if (empty($nm)) {
            $this->userXr($i);
        }
    }

    public function renXrUs($name, $uid)
    {
        if (($i = $this->xrIndex((string) $uid)) === null) {
            return $this->xray();
        }
        if (!$this->validName($name = trim((string) $name))) {
            $this->send($this->input['chat'], 'wrong name: letters, digits, emoji, space . _ @ -');
            return $this->userXr($i);
        }
        $c   = $this->getXray();
        $old = (string) ($c['inbounds'][0]['settings']['clients'][$i]['email'] ?? '');
        foreach ($c['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($k != $i && ($v['email'] ?? '') === $name) {
                $this->send($this->input['chat'], "user $name already exists");
                return $this->userXr($i);
            }
        }
        if ($old === $name) {
            return $this->userXr($i);
        }
        // Xray counts traffic by name: the record moves to the new name
        $c['inbounds'][0]['settings']['clients'][$i]['email'] = $name;
        $this->xrayApplyUsers($c, [$old, $name]);
        $this->adguardXrayClients();
        $this->userXr($i);
    }

    public function getXrayStats()
    {
        // no file yet: no traffic counted yet
        $f = BOT_DATA . '/xray.stats';
        return is_file($f) ? bot_read_json($f) : [];
    }

    public function setXrayStats($x)
    {
        bot_write_json(BOT_DATA . '/xray.stats', (array) $x, 0640, BOT_GID_WEB, 0);
    }

    public function resetXrUser($i)
    {
        $e = (string) ($this->getXray()['inbounds'][0]['settings']['clients'][$i]['email'] ?? '');
        $this->updateXrayStats(function ($p) use ($e) {
            foreach (['downlink', 'uplink'] as $d) {
                $this->ssh('xray api stats --server=127.0.0.1:8080 -reset -name ' . escapeshellarg("user>>>$e>>>traffic>>>$d") . ' >/dev/null 2>&1', 'xr');
            }
            $p['users'][$e] = [
                'session' => ['download' => 0, 'upload' => 0],
                'global'  => ['download' => 0, 'upload' => 0],
            ];
            return $p;
        });
        $this->userXr($i);
    }

    // all traffic to zero: Xray's counters through its API, no restart
    public function resetXrStats($nomenu = false)
    {
        $this->updateXrayStats(function ($p) {
            $this->ssh('xray api statsquery --server=127.0.0.1:8080 -pattern "" -reset > /dev/null 2>&1', 'xr');
            $st = [];
            if (($u = $this->xrayUptime()) !== null) {
                $st['xray_uptime'] = $u;
            }
            return $st;
        });
        if (empty($nomenu)) {
            $this->xray();
        }
    }

    public function listXr($i)
    {
        $c = $this->getPacConf();
        $c['xtlslist'] = $i;
        $this->setPacConf($c);
        $this->xray();
    }

    public function mainOutbound()
    {
        $this->prompt($this->i18n('send name'), $this->i18n('ph: send name'), 'setMainOutbound');
    }

    public function setMainOutbound($text)
    {
        $pac = $this->getPacConf();
        if (!empty($text)) {
            $pac['outbound'] = $text;
        } else {
            unset($pac['outbound']);
        }
        $this->setPacConf($pac);
        $this->xray();
    }

    public function xray($page = 0)
    {
        $c      = $this->getXray();
        $p      = $this->getPacConf();
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray');
        if (!empty($c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0])) {
            $text[] = "fake domain: <code>{$c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]}</code>";
        }
        $text[] = 'transport: ' . (($p['transport'] ?? null) ?: 'Websocket');
        $st = $this->getXrayStats();
        $td = $this->getBytes(($st['global']['download'] ?? 0) + ($st['session']['download'] ?? 0));
        $tu = $this->getBytes(($st['global']['upload'] ?? 0) + ($st['session']['upload'] ?? 0));
        $text[] = "↓$td  ↑$tu";
        $data[] = [
            [
                'text'          => $this->i18n('reset stats'),
                'callback_data' => '/resetXrStats',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('main outbound name: ') . ($p['outbound'] ?? 'proxy'),
                'callback_data' => '/mainOutbound',
            ],
        ];
        $ip_count = ($p['ip_count'] ?? null) ?: 1;
        // behind a bridge every client comes from the bridge's IP: no IP limit
        $data[]   = array_values(array_filter([
            [
                'text'          => $p['linkdomain'] ?? $this->i18n('cdn'),
                'callback_data' => '/addLinkDomain',
            ],
            empty($p['bridge']) ? [
                'text'          => $this->i18n('ip limit') . ' ' . (!empty($p['ip_limit']) ? ": {$p['ip_limit']} sec & $ip_count" : $this->i18n('off')),
                'callback_data' => "/setIpLimit",
            ] : null,
        ]));
        $data[] = [
            [
                'text'          => $this->i18n('RLTY') . ' ' . (($p['transport'] ?? null) == 'Reality' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport Reality",
            ],
            [
                'text'          => $this->i18n('WS') . ' ' . (($p['transport'] ?? null) == 'Websocket' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport Websocket",
            ],
            [
                'text'          => $this->i18n('XHTTP') . ' ' . (($p['transport'] ?? null) == 'xhttp' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport xhttp",
            ],
        ];

        if (($p['transport'] ?? null) == 'Reality') {
            $data[] = [
                [
                    'text'          => $this->i18n('changeFakeDomain'),
                    'callback_data' => "/changeFakeDomain",
                ],
                [
                    'text'          => $this->i18n('selfFakeDomain'),
                    'callback_data' => "/selfFakeDomain",
                ],
            ];
        }
        // sing-box has no XHTTP transport: its templates are hidden while XHTTP is on
        $data[] = array_values(array_filter([
            ($p['transport'] ?? '') != 'xhttp' ? [
                'text'          => $this->i18n('sing-box templates'),
                'callback_data' => "/templates sing",
            ] : null,
            [
                'text'          => $this->i18n('mihomo templates'),
                'callback_data' => "/templates clash",
            ],
        ]));
        $data[] = [
            [
                'text'          => $this->i18n('routes'),
                'callback_data' => "/routes",
            ],
        ];
        $on = $off = 0;
        foreach ($c['inbounds'][0]['settings']['clients'] as $k => $v) {
            if (!empty($v['off'])) {
                $off++;
            } else {
                $on++;
            }
        }
        $type    = !empty($this->getPacConf()['xtlslist']);
        $clients = array_filter($c['inbounds'][0]['settings']['clients'], fn($e) => !$type ? empty($e['off']) : !empty($e['off']));

        $all     = (int) ceil(count($clients) / $this->limit);
        $page    = min($page, $all - 1);
        $page    = $page == -2 ? $all - 1 : $page;
        $clients = $page != -1 ? array_slice($clients, $page * $this->limit, $this->limit, true) : $clients;
        foreach ($clients as $k => $v) {
            [$download, $upload] = array_map([$this, 'getBytes'], $this->userTraffic($st, $v));
            $data[]   = [
                [
                    'text'          => "{$v['email']} (↓$download  ↑$upload)",
                    'callback_data' => '/userXr ' . $this->xrUid($v),
                ],
            ];
        }
        if ($page != -1 && $all > 1) {
            $data[] = [
                [
                    'text'          => '<<',
                    'callback_data' => "/xray " . ($page - 1 >= 0 ? $page - 1 : $all - 1),
                ],
                [
                    'text'          => $page + 1,
                    'callback_data' => "/xray $page",
                ],
                [
                    'text'          => '>>',
                    'callback_data' => "/xray " . ($page < $all - 1 ? $page + 1 : 0),
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/addXrUser",
            ],
            [
                'text'          => $this->i18n('on') . " $on " . (!$type ? "✅" : ''),
                'callback_data' => "/listXr 0",
            ],
            [
                'text'          => $this->i18n('off') . " $off " . ($type ? "✅" : ''),
                'callback_data' => "/listXr 1",
            ],
        ];

        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function routes()
    {
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . ' -> ' . $this->i18n('routes');

        $data = [
            [[
                'text'          => $this->i18n('routes block'),
                'callback_data' => "/xtlsblock",
            ]],
            [[
                'text'          => $this->i18n('warp'),
                'callback_data' => "/xtlswarp",
            ]],
            [[
                'text'          => $this->i18n('rulesset'),
                'callback_data' => "/xtlsrulesset",
            ]],
            [[
                'text'          => $this->i18n('happ routing') . ': ' . (!empty($this->getPacConf()['happrouting']) ? 'MYrouting' : $this->i18n('off')),
                'callback_data' => '/happRouting',
            ]],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/xray",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }


    public function analyzeXray()
    {
        while (true) {
            try {
                $this->analyzeXrayRound();
            } catch (Throwable $e) {
                error_log("analyzeXray: $e");
            }
            @touch('/tmp/iplimit_heartbeat');
            sleep(10);
        }
    }

    // follows the Xray access log while the IP limit is on
    public function analyzeXrayRound()
    {
        if (empty($this->getPacConf()['ip_limit'])) {
            return;
        }
        $this->pool = [];
        $log = '/logs/xray';
        // Xray creates the log after its restart with the limit on
        if (!($r = @fopen($log, 'r'))) {
            return;
        }
        try {
            fseek($r, 0, SEEK_END);
            while (true) {
                @touch('/tmp/iplimit_heartbeat');
                $pac = $this->getPacConf();
                if (empty($pac['ip_limit'])) {
                    break;
                }
                $currentPosition = ftell($r);
                clearstatcache();
                $fileSize = (int) @filesize($log);
                if ($fileSize < $currentPosition) {
                    // the log was cleaned or rotated (copytruncate): read it from the start
                    fseek($r, 0);
                    $currentPosition = 0;
                }
                if ($fileSize > $currentPosition) {
                    fseek($r, $currentPosition); // сброс флага feof
                    while (!feof($r)) {
                        $line = fgets($r);
                        if ($line !== false) {
                            $this->frequencyAnalyze($line, $pac);
                        }
                    }
                }
                sleep(1);
            }
        } finally {
            fclose($r);
        }
    }

    public function frequencyAnalyze($line, $pac)
    {
        if (!empty($this->pool)) {
            foreach ($this->pool as $i => $j) {
                if (!empty($j['ips'])) {
                    foreach ($j['ips'] as $k => $v) {
                        if ($v + $pac['ip_limit'] < time()) {
                            unset($this->pool[$i]['ips'][$k]);
                        }
                    }
                }
            }
        }
        // "from 1.2.3.4:5678 accepted ... email: name" or "from [2001:db8::1]:5678 ..."
        if (empty(preg_match('~\sfrom\s(?:tcp:|udp:)?(?:\[(?<ip6>[0-9A-Fa-f:.]+)\]|(?<ip4>\d+\.\d+\.\d+\.\d+)):\d+\s.*?email:\s(?<email>.+)$~', trim($line), $m))) {
            return;
        }
        $m['ip'] = ($m['ip4'] ?? '') !== '' ? $m['ip4'] : ($m['ip6'] ?? '');
        if (!empty($m['ip']) && !empty($m['email'])) {
            $ip = $m['ip'];
            if (!empty($this->pool[$m['email']]['ip']) && $this->pool[$m['email']]['ip'] != $ip) {
                $this->pool[$m['email']]['ips'][$ip] = time();
            }
            if (!empty($this->pool[$m['email']]['ips']) && count($this->pool[$m['email']]['ips']) > (($pac['ip_count'] ?? null) ?: 1)) {
                $xr = $this->getXray();
                foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
                    if (empty($v['off']) && ($v['email'] ?? null) == $m['email']) {
                        // one alert per user in 30 minutes
                        if (time() - ($this->ipAlerted[$m['email']] ?? 0) < 1800) {
                            unset($this->pool[$m['email']]);
                            break;
                        }
                        $this->ipAlerted[$m['email']] = time();
                        $c = $this->config();
                        foreach ($c['admin'] as $admin) {
                            // the button shows the user's state (on): pressing it switches the user off
                            $this->send($admin, "vless: {$m['email']} limit ip " . count($this->pool[$m['email']]['ips']) . ' > ' . (($pac['ip_count'] ?? null) ?: 1), button: [[
                                [
                                    'text'          => $this->i18n(!empty($v['off']) ? 'off' : 'on') . ' ' . $this->i18n(!empty($v['off']) ? 'state off' : 'state on'),
                                    'callback_data' => '/switchXr ' . $this->xrUid($v),
                                ],
                            ]]);
                        }
                        unset($this->pool[$m['email']]);
                        break;
                    }
                }
            }
            $this->pool[$m['email']]['ip'] = $ip;
        }
    }

    public function userXr($i)
    {
        $xray   = $this->getXray();
        $c      = $xray['inbounds'][0]['settings']['clients'][$i] ?? null;
        if (empty($c)) {
            // the user is gone (deleted from another message): back to the list
            return $this->xray();
        }
        $pac    = $this->getPacConf();
        $pac['singtemplates']  = $this->getTemplates('sing');
        $pac['clashtemplates'] = $this->getTemplates('clash');
        $domain = $this->getDomain(($pac['transport'] ?? null) != 'Reality');
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        $name   = rawurlencode((string) ($c['email'] ?? ''));
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . ' -> ' . htmlspecialchars((string) ($c['email'] ?? ''));
        // sing-box has no XHTTP transport: no sing-box links while XHTTP is on
        $sing = ($pac['transport'] ?? '') != 'xhttp';

        $si = $this->subLink($scheme, $domain, 'si', $c['id']);
        $cl = $this->subLink($scheme, $domain, 'cl', $c['id']);

        $text[] = "\nVless:\n<pre><code>{$this->linkXray($i)}</code></pre>";
        if ($sing) {
            $text[] = "\nSing-box:\n<pre><code>$si</code></pre>";
        }
        $text[] = "\nMihomo:\n<pre><code>$cl</code></pre>";
        $text[] = "\nHapp:\n<pre><code>$scheme://{$domain}/pac$hash?t=hp&s={$c['id']}</code></pre>";
        $text[] = '';
        if ($sing) {
            $text[] = "<a href='$scheme://{$domain}/pac$hash?t=si&r=si&s={$c['id']}#$name'>import://sing-box</a>";
        }
        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=cl&r=c&s={$c['id']}#$name'>import://mihomo</a>";
        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=hp&r=hp&s={$c['id']}#$name'>import://happ</a>";

        $uid      = $this->xrUid($c);
        $st       = $this->getXrayStats();
        [$download, $upload] = array_map([$this, 'getBytes'], $this->userTraffic($st, $c));
        $data[]   = [
            [
                'text'          => $this->i18n('reset stats') . ": ↓$download  ↑$upload",
                'callback_data' => "/resetXrUser $uid",
            ],
        ];
        $data[] = array_values(array_filter([
            $sing ? [
                'text'    => $this->i18n('singbox'),
                'web_app' => ['url' => "https://{$domain}/pac$hash?t=si&s={$c['id']}"]
            ] : null,
            [
                'text'    => $this->i18n('mihomo'),
                'web_app' => ['url' => "https://{$domain}/pac$hash?t=cl&s={$c['id']}"]
            ],
        ]));
        $singtemplate  = !empty($c['singtemplate']) ? base64_decode($c['singtemplate']) : $this->i18n('default') . '(' . (!empty($pac['defaultsingtemplate']) && !empty($pac['singtemplates'][base64_decode($pac['defaultsingtemplate'])]) ? base64_decode($pac['defaultsingtemplate']) : $this->i18n('origin')) . ')';
        $clashtemplate = !empty($c['clashtemplate']) ? base64_decode($c['clashtemplate']) : $this->i18n('default') . '(' . (!empty($pac['defaultclashtemplate']) && !empty($pac['clashtemplates'][base64_decode($pac['defaultclashtemplate'])]) ? base64_decode($pac['defaultclashtemplate']) : $this->i18n('origin')) . ')';
        $data[]        = array_values(array_filter([
            $sing ? [
                'text'          => $this->i18n('singbox') . ": $singtemplate",
                'callback_data' => "/templateUser sing $uid",
            ] : null,
            [
                'text'          => $this->i18n('mihomo') . ": $clashtemplate",
                'callback_data' => "/templateUser clash $uid",
            ],
        ]));
        if ($sing) {
            $data[] = [
                [
                    'text'          => $this->i18n('qr singbox'),
                    'callback_data' => "/qrXray {$uid}_2",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('new subscription link'),
                'callback_data' => "/newSubXr $uid",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('rename'),
                'callback_data' => "/renameXrUser $uid",
            ],
            [
                // the user's state, pressing it switches the user on/off
                'text'          => $this->i18n(!empty($c['off']) ? 'off' : 'on') . ' ' . $this->i18n(!empty($c['off']) ? 'state off' : 'state on'),
                'callback_data' => "/switchXr $uid",
            ],
            [
                'text'          => $this->i18n('delete'),
                'callback_data' => "/delxr $uid",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/xray",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function getXray()
    {
        return bot_read_json(BOT_DATA . ($this->web ? '/web/xray.json' : '/xray/xray.json'));
    }

    /**
     * The Xray config as the bot keeps it (Xray reads it as /xray/xray.json)
     * and its copy for the web pools, which build the subscriptions from
     * it: without the Reality private key.
     */
    public function saveXray(array $c)
    {
        bot_write_json(BOT_DATA . '/xray/xray.json', $c);
        $this->saveXrayView($c);
    }

    public function saveXrayView(array $c)
    {
        foreach ($c['inbounds'] ?? [] as $k => $v) {
            unset($c['inbounds'][$k]['streamSettings']['realitySettings']['privateKey']);
        }
        bot_write_json(BOT_DATA . '/web/xray.json', $c, 0640, BOT_GID_WEB);
    }

    public function changeFakeDomain()
    {
        $this->prompt($this->i18n('enter domain'), $this->i18n('enter domain'), 'setFakeDomain');
    }

    public function setFakeDomain($domain, $self = false)
    {
        // goes into the upstream SNI map and the Reality settings
        if (!$this->validHost($domain = trim((string) $domain))) {
            $this->send($this->input['chat'], 'wrong domain');
            return;
        }
        $c = $this->getXray();
        $p = $this->getPacConf();
        $c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0] = $domain;
        $c['inbounds'][0]['streamSettings']['realitySettings']['dest'] = $self ? "10.10.1.2:443" : "$domain:443";
        $p['reality']['domain'] = $domain;
        $p['reality']['destination'] = $self ? "10.10.1.2:443" : "$domain:443";
        $this->setPacConf($p);
        $this->restartXray($c);
        $this->setUpstreamDomain($domain);
        $this->xray();
    }

    public function selfFakeDomain()
    {
        $c = $this->getPacConf();
        if (!empty($c['domain'])) {
            $this->setFakeDomain($c['domain'], 1);
        } else{
            $this->answer($this->input['callback_id'], 'empty domain', true);
        }
    }

    public function changeTransport($transport)
    {
        $p = $this->getPacConf();
        $x = $this->getXray();
        $h = $this->getHashBot();

        $p['reality']['domain']      = ($p['reality']['domain'] ?? null) ?: 'yandex.ru';
        $p['reality']['destination'] = ($p['reality']['destination'] ?? null) ?: $p['reality']['domain'] . ':443';
        $p['transport'] = $transport;

        $p['reality']['domain']      = $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0] ?? $p['reality']['domain'];
        $p['reality']['destination'] = $x['inbounds'][0]['streamSettings']['realitySettings']['dest'] ?? $p['reality']['destination'];
        $p['reality']['shortId']     = $x['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0] ?? $p['reality']['shortId'];

        if (empty($p['xray']) || $this->secret('reality_privateKey') === '') {
            $shortId = trim($this->ssh('openssl rand -hex 8', 'xr'));
            $keys    = $this->ssh('xray x25519', 'xr');
            // output differs between xray versions:
            // "Private key: / Public key:", "PrivateKey: / Password:",
            // "PrivateKey: / Password (PublicKey):"
            preg_match('~^Private\s?key:\s*(\S+)~mi', $keys, $m);
            $private = trim($m[1] ?? '');
            preg_match('~^(?:Public\s?key|Password(?:\s*\(PublicKey\))?):\s*(\S+)~mi', $keys, $m);
            $public = trim($m[1] ?? '');
            $p['xray'] = $public;
            $p['reality']['shortId']    = $shortId;
            $this->setSecret('reality_privateKey', $private);
        }


        switch ($transport) {
            case 'xhttp':
                foreach ($x['inbounds'][0]['settings']['clients'] as $k => $v) {
                    unset($x['inbounds'][0]['settings']['clients'][$k]['flow']);
                }
                $x['inbounds'][0]['streamSettings'] = [
                    "network"       => "xhttp",
                    "xhttpSettings" => [
                        "mode"  => "auto",
                        "path"  => "/ws$h",
                        "extra" => [
                            "noSSEHeader"          => true,
                            "xPaddingBytes"        => "100-1000",
                            "scMaxBufferedPosts"   => 30,
                            "scMaxEachPostBytes"   => 1000000,
                            "scStreamUpServerSecs" => "20-80"
                        ]
                    ]
                ];
                break;

            case 'Reality':
                foreach ($x['inbounds'][0]['settings']['clients'] as $k => $v) {
                    $x['inbounds'][0]['settings']['clients'][$k]['flow'] = 'xtls-rprx-vision';
                }
                $x['inbounds'][0]['streamSettings'] = [
                    "network"         => "tcp",
                    "realitySettings" => [
                        "dest"         => ($p['reality']['destination'] ?? null) ?: $x['inbounds'][0]['streamSettings']['realitySettings']['dest'],
                        "maxClientVer" => "",
                        "maxTimeDiff"  => 0,
                        "minClientVer" => "",
                        "privateKey"   => $this->secret('reality_privateKey'),
                        "serverNames"  => [
                            ($p['reality']['domain'] ?? null) ?: $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]
                        ],
                        "shortIds" => [$p['reality']['shortId']] ?: $x['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0],
                        "show"     => false,
                        "xver"     => 0
                    ],
                    "tcpSettings" => [
                        "acceptProxyProtocol" => true
                    ],
                    "sockopt" => [
                        "acceptProxyProtocol" => true
                    ],
                    "security" => "reality"
                ];
                break;

            default:
                $x['inbounds'][0]['streamSettings'] = [
                    "network"    => "ws",
                    "wsSettings" => [
                        "path" => "/ws$h"
                    ]
                ];
                foreach ($x['inbounds'][0]['settings']['clients'] as $k => $v) {
                    unset($x['inbounds'][0]['settings']['clients'][$k]['flow']);
                }
                break;
        }

        $this->setUpstreamDomain($transport == 'Reality'
            ? (($p['reality']['domain'] ?? null) ?: $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0])
            : 't'
        );
        $this->setPacConf($p);
        $this->restartXray($x);
        $this->xray();
    }
}
