<?php

// Logs, log analysis, block and ignore lists of addresses: methods of class Bot (app/bot.php)
trait BotLogs
{
    public function autoAnalyzeLogs()
    {
        try {
            $pac = $this->getPacConf();
            if (!empty($pac['autoscan'])) {
                $c = $this->config();
                // set by earlier versions: maybe below the 5 minutes
                if (!empty($c['admin']) && (empty($this->time3) || ((time() - $this->time3) > max(300, (int) ($pac['autoscan_timeout'] ?? 3600))))) {
                    $this->time3 = time();
                    $r = $this->analysisIp(return: 1);
                    if (!empty($r)) {
                        $t    = [];
                        $text = '';
                        $ban  = 0;
                        $ips  = [];
                        foreach ($r as $k => $v) {
                            foreach ($v as $i) {
                                $t[$i['title']][$k] = 1;
                            }
                        }
                        foreach ($t as $k => $v) {
                            $text .= "\n" . count($v) . " $k";
                        }
                        if (!empty($pac['autodeny'])) {
                            $this->denyIp(array_keys($r));
                            $ban = count(array_keys($r));
                            foreach (array_keys($r) as $v) {
                                $ips[] = [[
                                    'text'          => $v,
                                    'callback_data' => "/searchLogs $v",
                                ]];
                            }
                        }
                        if (($pac['silence'] ?? null) == 0 || ($pac['silence'] ?? null) == 1) {
                            foreach ($c['admin'] as $k => $v) {
                                $this->send($v, "suspicious ips found: $text" . ($ban ? "\nbanned:$ban" : ''), button: $ips ?: [[
                                    [
                                        'text'          => $this->i18n('analyze'),
                                        'callback_data' => '/analysisIp',
                                    ],
                                ]], disable_notification: !empty($pac['silence']) ? true : false);
                            }
                        }
                    }
                }
            }
        } catch (Throwable $e) {
            // appended to /logs/php_error (php.ini error_log), not over it
            error_log("autoAnalyzeLogs: $e");
        }
    }

    public function switchBanIp()
    {
        $c = $this->getPacConf();
        $c['autodeny'] = !empty($c['autodeny']) ? 0 : 1;
        $this->setPacConf($c);
        $this->ipMenu();
    }

    public function switchSilence()
    {
        $c = $this->getPacConf();
        $c['silence'] = ((($c['silence'] ?? null) ?: 0) + 1) % 3;
        $this->setPacConf($c);
        $this->ipMenu();
    }

    public function ipMenu()
    {
        $text   = $this->i18n('config') . ' -> ' . $this->i18n('IP & Logs');
        $pac    = $this->getPacConf();
        $d      = count(($pac['deny'] ?? null) ?: []);
        $w      = count(($pac['white'] ?? null) ?: []);
        $data[] = [
            [
                'text'          => $this->i18n('autoscan') . ': ' . (!empty($pac['autoscan']) ? $this->getTime(strtotime((($pac['autoscan_timeout'] ?? null) ?: 3600) . ' seconds')) : $this->i18n('off')),
                'callback_data' => '/autoScanTimeout',
            ],
        ];
        if (!empty($pac['autoscan'])) {
            $data[] = [
                [
                    'text'          => $this->i18n('autoblock') . ': ' . $this->i18n(!empty($pac['autodeny']) ? 'on' : 'off'),
                    'callback_data' => '/switchBanIp',
                ],
                [
                    'text'          => $this->i18n('notify') . ': ' . ((function ($pac) {
                        switch ($pac['silence'] ?? 0) {
                            case 0:
                                return '🔊';
                            case 1:
                                return '🔈';
                            case 2:
                                return '🔇';
                        }
                    })($pac)),
                    'callback_data' => '/switchSilence',
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('ignorelist') . ": $w",
                'callback_data' => '/denyList 0 1',
            ],
            [
                'text'          => $this->i18n('blocklist') . ": $d",
                'callback_data' => '/denyList 0 0',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('analyze'),
                'callback_data' => '/analysisIp',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function ipInRange($ip, $range) {
        [$range, $netmask] = explode('/', $range, 2);
        $rangeDecimal      = ip2long($range);
        $ipDecimal         = ip2long($ip);
        $wildcardDecimal   = pow(2, 32 - $netmask) - 1;
        $netmaskDecimal    = ~$wildcardDecimal;
        return ($ipDecimal & $netmaskDecimal) == ($rangeDecimal & $netmaskDecimal);
    }

    public function suspicious($regexp, $file, $ranges, $title, $reverse = false)
    {
        $ret = [];
        if (is_array($ranges)) {
            // single addresses looked up as keys, only real ranges compared
            $exact = [];
            $nets  = [];
            foreach ($ranges as $range) {
                if (str_ends_with($range, '/32')) {
                    $exact[substr($range, 0, -3)] = true;
                } else {
                    $nets[] = $range;
                }
            }
        }
        if ($r = @fopen($file, 'r')) {
            while (($l = fgets($r)) !== false) {
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)~', $l, $m)) {
                    if ($reverse xor preg_match($regexp, $l)) {
                        if (is_array($ranges)) {
                            $flag = !isset($exact[$m[1]]);
                            foreach ($flag ? $nets : [] as $range) {
                                if ($this->ipInRange($m[1], $range)) {
                                    $flag = false;
                                    break;
                                }
                            }
                            if ($flag) {
                                $ret[$m[1]][] = [
                                    'title' => $title,
                                    'log'   => $l,
                                ];
                            }
                        } else {
                            if ($this->ipInRange($m[1], $ranges)) {
                                $ret[$m[1]][] = [
                                    'title' => $title,
                                    'log'   => $l,
                                ];
                            }
                        }
                    }
                }
            }
            fclose($r);
        }
        return $ret ?: [];
    }

    /**
     * Suspicious addresses in the access logs (not on the white or block
     * lists, not seen as clients): [ip => [[title, log], ...]]. Reads the
     * whole logs: run in the cron loop or in the background (task.php).
     */
    public function analysisScan(): array
    {
        $pac = $this->getPacConf();
        // known addresses as keys (a set): the logs have thousands of lines
        $xr  = [];
        foreach (array_merge(($pac['white'] ?? null) ?: [], ($pac['deny'] ?? null) ?: [], ['10.10.0.0/23']) as $v) {
            if (preg_match('~^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:(/\d{1,2}))?$~', $v, $m)) {
                $xr[$m[1] . (($m[2] ?? null) ?: '/32')] = true;
            }
        }
        if ($r = @fopen('/logs/nginx_doh_access', 'r')) {
            while (($l = fgets($r)) !== false) {
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)~', $l, $m)) {
                    $xr["{$m[1]}/32"] = true;
                }
            }
            fclose($r);
        }
        if ($r = @fopen('/logs/xray', 'r')) {
            while (($l = fgets($r)) !== false) {
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)(?=.+accepted)~', $l, $m)) {
                    $xr["{$m[1]}/32"] = true;
                }
            }
            fclose($r);
        }
        $xr = array_keys($xr);

        $t = [
            $this->suspicious($this->reg, '/logs/nginx_default_access', $xr, 'possibly a scanner', true),
            $this->suspicious($this->reg, '/logs/nginx_domain_access', $xr, 'possibly a scanner', true),
        ];

        $ip = [];
        foreach ($t as $r) {
            foreach ($r as $k => $v) {
                $ip[$k] = $v;
            }
        }

        $r = $this->suspicious('~\d+\.\d+\.\d+\.\d+.+200\s\d+\s0$~', '/logs/upstream_access', $xr, 'possibly a Reality Degenerate');
        if (!empty($r)) {
            foreach ($r as $k => $v) {
                if (count($v) > 30) {
                    $ip[$k] = $v;
                }
            }
        }

        return $ip;
    }

    /**
     * The analysis menu. The logs are read in the background (they can be
     * large): the menu shows the last scan if it is under 10 minutes old,
     * otherwise (or with $new) a scan starts and updates this message.
     */
    public function analysisIp(int $page = 0, $return = false, $new = false)
    {
        if (!empty($return)) {
            return $this->analysisScan();
        }
        $cache = is_file($this->analysisCache) ? json_decode((string) @file_get_contents($this->analysisCache), true) : null;
        if ($new || !is_array($cache) || time() - (int) ($cache['time'] ?? 0) > 600) {
            $this->update($this->input['from'], $this->input['message_id'], 'reading the logs...');
            return $this->logTask('analysis', (string) $page);
        }
        $pac = $this->getPacConf();
        $ip  = [];
        foreach ((array) ($cache['ip'] ?? []) as $k => $n) {
            // blocked or ignored since the scan: no longer in the list
            foreach (array_merge(($pac['white'] ?? null) ?: [], ($pac['deny'] ?? null) ?: []) as $v) {
                $v = (string) $v;
                if ($v === $k || (str_contains($v, '/') && filter_var($k, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
                    && filter_var(explode('/', $v)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && $this->ipInRange($k, $v))) {
                    continue 2;
                }
            }
            $ip[$k] = $n;
        }
        if (!empty($ip)) {
            foreach ($ip as $k => $v) {
                $data[] = [
                    [
                        'text'          => $k,
                        'callback_data' => "/searchLogs $k a $page 0",
                    ]
                ];
            }
            $all  = (int) ceil(count($data) / $this->limit);
            $page = min($page, $all - 1);
            $page = $page < 0 ? $all - 1 : $page;
            $data = array_slice($data ?: [], $page * $this->limit, $this->limit);
            if ($all > 1) {
                $data[] = [
                    [
                        'text'          => '<<',
                        'callback_data' => "/analysisIp " . ($page - 1 >= 0 ? $page - 1 : $all - 1),
                    ],
                    [
                        'text'          => $page + 1,
                        'callback_data' => "/analysisIp $page",
                    ],
                    [
                        'text'          => '>>',
                        'callback_data' => "/analysisIp " . ($page < $all - 1 ? $page + 1 : 0),
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => '🔄 ' . date('H:i', (int) $cache['time']),
                'callback_data' => "/analysisIp 0 new",
            ],
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/ipMenu",
            ],
        ];
        $this->update($this->input['from'], $this->input['message_id'], count($ip) ?: 'empty', $data);
    }

    public function searchLogs($search, $fun = false, $page = 0, $white = 0)
    {
        if (filter_var($search, FILTER_VALIDATE_IP)) {
            // nothing goes to ipinfo.io unless the ipinfo button is pressed
            $text = "<code>$search</code>";
            $data[] = [
                [
                    'text'          => 'ipinfo.io',
                    'callback_data' => "/ipInfo $search",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('block'),
                    'callback_data' => "/denyIp $search" . ($fun ? " $fun $page $white" : ''),
                ],
                [
                    'text'          => $this->i18n('ignore'),
                    'callback_data' => "/whiteIp $search" . ($fun ? " $fun $page $white" : ''),
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('all logs'),
                    'callback_data' => "/searchIp $search",
                ],
                [
                    'text'          => $this->i18n('suspicious log'),
                    'callback_data' => "/searchSuspiciousIp $search",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('clean logs') . " $search",
                    'callback_data' => "/cleanLogs $search",
                ],
            ];
            if (!empty($fun)) {
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => $this->ipBackData($fun, $page, $white),
                    ],
                ];
                $this->update($this->input['from'], $this->input['message_id'], $text, button: $data);
            } else {
                if (empty($this->input['callback_id'])) {
                    $this->delete($this->input['from'], $this->input['message_id']);
                }
                $this->send($this->input['from'], $text, button: $data);
            }
        }
    }

    // what ipinfo.io knows about the address: only on the button
    public function ipInfo($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        $info = @file_get_contents("https://ipinfo.io/$ip/json", context: stream_context_create(['http' => ['timeout' => 3]]));
        $this->send($this->input['chat'], "$ip\n<pre>" . htmlspecialchars((string) $info ?: 'no answer') . '</pre>', $this->input['message_id']);
        $this->answer($this->input['callback_id']);
    }

    // every log line with the address, as a file (task.php logs ip)
    public function searchIp($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return $this->answer($this->input['callback_id'], 'wrong address');
        }
        $this->answer($this->input['callback_id'], 'reading the logs: a file follows');
        $this->logTask('ip', $ip);
    }

    // the suspicious log lines of the address, as a file (task.php logs suspicious)
    public function searchSuspiciousIp($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->answer($this->input['callback_id'], 'wrong address');
        }
        $this->answer($this->input['callback_id'], 'reading the logs: a file follows');
        $this->logTask('suspicious', $ip);
    }

    // a log scan in the background: the bot keeps answering meanwhile
    public function logTask(string $kind, string $arg)
    {
        $chat = (int) ($this->input['chat'] ?? $this->input['from'] ?? 0);
        $msg  = (int) ($this->input['message_id'] ?? 0);
        exec('cd /app && nohup php task.php logs ' . escapeshellarg($kind) . ' ' . escapeshellarg($arg) . " $chat $msg > /dev/null 2>&1 &");
    }

    /**
     * Runs in task.php: the analysis (its cache, then the menu in the same
     * message) or the lines of one address, sent as a text file.
     */
    public function logScan(string $kind, string $arg)
    {
        $chat = (int) $this->input['chat'];
        if ($kind === 'analysis') {
            $ip = array_map('count', $this->analysisScan());
            bot_write($this->analysisCache, json_encode(['time' => time(), 'ip' => $ip ?: new stdClass()]));
            return $this->analysisIp((int) $arg);
        }
        if (!filter_var($arg, FILTER_VALIDATE_IP)) {
            return;
        }
        $res = [];
        if ($kind === 'ip') {
            foreach ($this->logs as $v) {
                if ($r = @fopen("/logs/$v", 'r')) {
                    while (($l = fgets($r)) !== false) {
                        if (preg_match($this->ipRegex($arg), $l)) {
                            $res[$v][] = $l;
                        }
                    }
                    fclose($r);
                }
            }
        } elseif ($kind === 'suspicious') {
            foreach ([
                $this->suspicious('~\d+\.\d+\.\d+\.\d+.+200\s\d+\s0$~', '/logs/upstream_access', "$arg/32", 'possibly a Reality Degenerate'),
                $this->suspicious($this->reg, '/logs/nginx_default_access', "$arg/32", 'possibly a scanner', true),
                $this->suspicious($this->reg, '/logs/nginx_domain_access', "$arg/32", 'possibly a scanner', true),
            ] as $r) {
                foreach ((array) $r as $v) {
                    foreach ($v as $k) {
                        $res[$k['title']][] = $k['log'];
                    }
                }
            }
        }
        if (!$res) {
            return $this->send($chat, "<code>$arg</code>: nothing found");
        }
        // Telegram takes documents up to 50 MB; a few MB are enough to read
        $text = '';
        $max  = 10 * 1048576;
        foreach ($res as $k => $v) {
            $text .= "== $k: " . count($v) . " lines\n" . implode('', $v) . "\n";
            if (strlen($text) > $max) {
                $text = substr($text, 0, $max) . "\n... cut at 10 MB\n";
                break;
            }
        }
        $this->upload(($kind === 'ip' ? 'logs' : 'suspicious') . '_' . str_replace(':', '-', $arg) . '.txt', $text, $chat);
    }

    public function importIps($type)
    {
        $domains = [];
        switch ($type) {
            case 'telegram':
                $r = file_get_contents('https://core.telegram.org/resources/cidr.txt');
                if (!empty($r)) {
                    $domains = explode("\n", $r);
                }
                break;
            case 'gcore':
                $r = json_decode(file_get_contents('https://api.gcore.com/cdn/public-ip-list'), true);
                if (!empty($r['addresses'])) {
                    $domains = $r['addresses'];
                }
                break;
            case 'cloudflare':
                $r = json_decode(file_get_contents('https://api.cloudflare.com/client/v4/ips'), true);
                if (!empty($r['result']['ipv4_cidrs'])) {
                    $domains = $r['result']['ipv4_cidrs'];
                }
                break;
        }
        if (!empty($domains = array_filter($domains ?: [], fn($e) => preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}~', $e)))) {
            $this->addInclude(implode(',', $domains), 'white');
        } else {
            $this->answer($this->input['callback_id'], "$type: download failed", true);
        }
    }

    public function denyList($page = 0, $white = 0)
    {
        $text    = $this->i18n('Menu') . ' -> IP -> ' . $this->i18n($white ? 'ignorelist' : 'blocklist');
        $domains = $this->getPacConf()[$white ? 'white' : 'deny'] ?: [];
        $all     = (int) ceil(count($domains) / $this->limit);
        $page    = min($page, $all - 1);
        $page    = $page < 0 ? $all - 1 : $page;

        if (!empty($white)) {
            $data[] = [
                [
                    'text'          => $this->i18n('telegram IPs'),
                    'callback_data' => "/importIps telegram",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('gcore IPs'),
                    'callback_data' => "/importIps gcore",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('cloudflare IPs'),
                    'callback_data' => "/importIps cloudflare",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/include " . ($white ? 'white' : 'deny'),
            ],
        ];
        if (!empty($domains)) {
            foreach (array_slice($domains, $page * $this->limit, $this->limit) as $v) {
                $data[] = [
                    [
                        'text'          => $v,
                        'callback_data' => "/searchLogs $v d $page $white",
                    ],
                    [
                        'text'          => $this->i18n('delete'),
                        'callback_data' => "/allowIp $v $page" . ($white ? " 1" : ''),
                    ],
                ];
            }
            if ($all > 1) {
                $data[] = [
                    [
                        'text'          => '<<',
                        'callback_data' => "/denyList " . ($page - 1 >= 0 ? $page - 1 : $all - 1) . ($white ? " 1" : ' 0'),
                    ],
                    [
                        'text'          => $page + 1,
                        'callback_data' => "/denyList $page" . ($white ? " 1" : ' 0'),
                    ],
                    [
                        'text'          => '>>',
                        'callback_data' => "/denyList " . ($page < $all - 1 ? $page + 1 : 0) . ($white ? " 1" : ' 0'),
                    ],
                ];
            }
            $data[] = [
                [
                    'text'          => $this->i18n('delete all'),
                    'callback_data' => "/cleanDeny" . ($white ? " 1" : ''),
                ],
            ];
        }

        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/ipMenu",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function cleanDeny($white = 0)
    {
        $pac = $this->getPacConf();
        unset($pac[$white ? 'white' : 'deny']);
        $this->setPacConf($pac);
        $this->syncDeny();
        $this->ipMenu();
    }

    /**
     * The menu to go back to after a button in an IP card: a short code in
     * the button data (a analysis, d block/ignore list), a known method
     * only, never a name taken from the data as it is.
     */
    public function ipBack($fun, $page = 0, $white = 0)
    {
        switch ($fun) {
            case 'a':
            case 'analysisIp':
                return $this->analysisIp((int) $page);
            case 'd':
            case 'denyList':
                return $this->denyList((int) $page, (int) $white);
        }
    }

    // the callback that opens that menu
    public function ipBackData($fun, $page = 0, $white = 0): string
    {
        return in_array($fun, ['d', 'denyList'], true) ? "/denyList $page " . ($white ? 1 : 0) : "/analysisIp $page";
    }

    public function denyIp($ip, $fun = false, $page = 0, $white = 0)
    {
        if (!is_array($ip) && !$this->validIpOrCidr($ip)) {
            return $this->answer($this->input['callback_id'], 'wrong IP', true);
        }
        $pac = $this->getPacConf();
        if (is_array($ip)) {
            foreach ($ip as $v) {
                $pac['deny'][] = $v;
                if (($t = array_search($v, ($pac['white'] ?? null) ?: [])) !== false) {
                    unset($pac['white'][$t]);
                }
            }
        } else {
            $pac['deny'][] = $ip;
            if (($t = array_search($ip, ($pac['white'] ?? null) ?: [])) !== false) {
                unset($pac['white'][$t]);
            }
        }
        $this->setPacConf($pac);
        // the message with the button; the cron's autoblock has none
        if (empty($fun) && !empty($this->input['message_id'])) {
            $this->delete($this->input['from'], $this->input['message_id']);
        }
        $this->syncDeny();
        if (!empty($fun)) {
            $this->ipBack($fun, $page, $white);
        }
    }

    public function whiteIp($ip, $fun = false, $page = 0, $white = 0)
    {
        if (!is_array($ip) && !$this->validIpOrCidr($ip)) {
            return $this->answer($this->input['callback_id'], 'wrong IP', true);
        }
        $pac = $this->getPacConf();
        if (is_array($ip)) {
            foreach ($ip as $v) {
                $pac['white'][] = $v;
                if (($t = array_search($v, ($pac['deny'] ?? null) ?: [])) !== false) {
                    unset($pac['deny'][$t]);
                }
            }
        } else {
            $pac['white'][] = $ip;
            if (($t = array_search($ip, ($pac['deny'] ?? null) ?: [])) !== false) {
                unset($pac['deny'][$t]);
            }
        }
        $this->setPacConf($pac);
        // the message with the button; the cron's autoblock has none
        if (empty($fun) && !empty($this->input['message_id'])) {
            $this->delete($this->input['from'], $this->input['message_id']);
        }
        $this->syncDeny();
        if (!empty($fun)) {
            $this->ipBack($fun, $page, $white);
        }
    }

    public function allowIp($ip, $page, $white = 0)
    {
        $pac  = $this->getPacConf();
        $list = $white ? 'white' : 'deny';
        // only this address: array_search gives false for one removed meanwhile
        if (($k = array_search($ip, $pac[$list] ?? [], true)) !== false) {
            unset($pac[$list][$k]);
            $pac[$list] = array_values($pac[$list]);
            $this->setPacConf($pac);
            $this->syncDeny();
        }
        $this->denyList($page, $white);
    }

    // a regex that finds the address itself, not a longer one containing it
    public function ipRegex(string $ip): string
    {
        return strpos($ip, ':') !== false
            ? '~(?<![0-9A-Fa-f:])' . preg_quote($ip, '~') . '(?![0-9A-Fa-f:])~'
            : '~(?<![\d.])' . preg_quote($ip, '~') . '(?![\d])~';
    }

    public function cleanLogs($ip, $nodelete = false)
    {
        // drop lines with $ip line by line (logs can be large), without a
        // shell; written back into the same file: nginx and Xray keep it open
        if ($this->validIpOrCidr($ip) && strpos($ip, '/') === false) {
            $re = $this->ipRegex($ip);
            foreach ($this->logs as $v) {
                $f = "/logs/$v";
                if (!is_file($f) || !($in = fopen($f, 'r+'))) {
                    continue;
                }
                $tmp = fopen('php://temp', 'w+');
                while (($l = fgets($in)) !== false) {
                    if (!preg_match($re, $l)) {
                        fwrite($tmp, $l);
                    }
                }
                ftruncate($in, 0);
                rewind($in);
                rewind($tmp);
                stream_copy_to_stream($tmp, $in);
                fclose($tmp);
                fclose($in);
            }
        }
        if (empty($nodelete)) {
            $this->delete($this->input['from'], $this->input['message_id']);
        }
    }

    /**
     * An IPv4/IPv6 address or CIDR: the only thing allowed into the nginx
     * allow/deny include.
     */
    public function validIpOrCidr($v): bool
    {
        if (!is_string($v) || !preg_match('~^([0-9A-Fa-f:.]+)(?:/(\d{1,3}))?$~D', $v, $m)) {
            return false;
        }
        if (filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return !isset($m[2]) || (int) $m[2] <= 32;
        }
        if (filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return !isset($m[2]) || (int) $m[2] <= 128;
        }
        return false;
    }

    public function syncDeny()
    {
        $pac = $this->getPacConf();
        $pac['white'] = array_values(array_filter(($pac['white'] ?? null) ?: [], [$this, 'validIpOrCidr']));
        $pac['deny']  = array_values(array_filter(($pac['deny'] ?? null) ?: [], [$this, 'validIpOrCidr']));
        $text = '';
        if (!empty($pac['white'])) {
            $pac['white'] = array_unique($pac['white']);
            sort($pac['white']);
            foreach ($pac['white'] as $v) {
                $text .= "allow $v;\n";
            }
        }
        if (!empty($pac['deny'])) {
            $pac['deny'] = array_unique($pac['deny']);
            sort($pac['deny']);
            foreach ($pac['deny'] as $k => $v) {
                if (!in_array($v, ($pac['white'] ?? null) ?: [])) {
                    $text .= "deny $v;\n";
                } else {
                    unset($pac['deny'][$k]);
                }
            }
        }
        $this->setPacConf($pac);
        // tested with a copy of upstream.conf that includes the new list
        $up = BOT_DATA . '/up/upstream.conf';
        bot_write("$up.test", str_replace('include /etc/nginx/bot/deny;', 'include /etc/nginx/bot/deny.new;', $this->upstreamConf(bot_read($up))));
        $ok = $this->applyConfig(BOT_DATA . '/up/deny', $text ?: '', 'up', 'nginx -t -q -c /etc/nginx/bot/upstream.conf.test');
        @unlink("$up.test");
        if ($ok) {
            $this->ssh(self::NGINX_UP . ' -s reload', 'up');
        }
        // the ignorelist is also free of the request limits in ng
        $ng = BOT_DATA . '/ng/nginx.conf';
        if (is_file($ng)) {
            bot_write("$ng.test", str_replace('include /etc/nginx/bot/limit_exempt.conf;', 'include /etc/nginx/bot/limit_exempt.conf.new;', bot_read($ng)));
            $ok = $this->applyConfig(BOT_DATA . '/ng/limit_exempt.conf', $this->limitExemptConf(), 'ng', 'nginx -t -q -c /etc/nginx/bot/nginx.conf.test');
            @unlink("$ng.test");
            if ($ok) {
                $this->ssh(self::NGINX_NG . ' -s reload', 'ng');
            }
        }
    }

    // geo entries for nginx: the ignorelist (with the bridge IP) has no request limits
    public function limitExemptConf(): string
    {
        $pac = $this->getPacConf();
        $ips = array_filter(array_merge($pac['white'] ?? [], [$pac['bridge'] ?? '']), [$this, 'validIpOrCidr']);
        return implode('', array_map(fn($v) => "$v 1;\n", array_values(array_unique($ips))));
    }

    public function autoScanTimeout()
    {
        $this->prompt($this->i18n('send time like 1 hour or 1 day etc'), $this->i18n('ph: send time like 1 hour or 1 day etc'), 'setAutoScanTimeout');
    }

    public function setAutoScanTimeout($time)
    {
        $pac = $this->getPacConf();
        $t   = empty($time) ? 0 : strtotime($time, 0);
        if (empty($time)) {
            unset($pac['autoscan_timeout']);
            unset($pac['autoscan']);
        } elseif ($t >= 300) {
            // five minutes at least: each scan reads the whole access logs
            $pac['autoscan_timeout'] = $t;
            $pac['autoscan'] = 1;
        } else {
            $this->send($this->input['from'], htmlspecialchars($time) . ' - wrong format, 5 minutes at least', $this->input['message_id']);
        }
        $this->setPacConf($pac);
        $this->ipMenu();
    }

    /**
     * The logs, rotated by the cron loop (rotateLogs): a week, at most 50
     * MB per file. The menu lists the current files; the size includes the
     * rotated copies. Cleaning a log removes its copies too.
     */
    public function logs()
    {
        foreach (scandir('/logs/') as $v) {
            if ($this->logFile($v) === null || preg_match('~\.(\d+|\d+\.gz)$~', $v)) {
                continue;
            }
            $size = 0;
            foreach (array_merge(["/logs/$v"], $this->logCopies($v)) as $f) {
                $size += (int) @filesize($f);
            }
            $data[] = [
                [
                    'text'          => $this->getBytes($size) . " $v",
                    'callback_data' => "/getLog $v",
                ],
                [
                    'text'          => $this->i18n('clean'),
                    'callback_data' => "/clearLog $v",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('clean all'),
                'callback_data' => "/cleanLog",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $this->i18n('logs') . ': 7 ' . $this->i18n('days') . ', ≤ 50 MB',
            $data ?: false,
        );
    }

    // rotated copies of a log: name.1, name.2.gz ...
    public function logCopies(string $name): array
    {
        return array_values(array_filter(glob('/logs/' . str_replace(['*', '?', '['], '', $name) . '.*') ?: [], fn($f) => preg_match('~\.(\d+|\d+\.gz)$~', $f) && is_file($f)));
    }

    // cron loop: logrotate (system/logrotate.conf) every 15 minutes
    public function rotateLogs()
    {
        if (!empty($this->time_logrotate) && time() - $this->time_logrotate < 900) {
            return;
        }
        $this->time_logrotate = time();
        exec('logrotate -s ' . escapeshellarg(BOT_DATA . '/logrotate.status') . ' /system/logrotate.conf 2>&1', $out, $code);
        if ($code) {
            error_log('logrotate: ' . implode("\n", $out));
        }
    }

    // a log in /logs by its name: a plain file there, not a dot file
    public function logFile($name): ?string
    {
        $name = (string) $name;
        return preg_match('~^[\w-][\w.-]{0,47}$~D', $name) && is_file("/logs/$name") && !is_link("/logs/$name") ? "/logs/$name" : null;
    }

    /**
     * A log as a file. Telegram takes files up to 50 MB: a bigger one is
     * sent gzip-compressed, and if that is still too big, its last part.
     */
    public function getLog($name)
    {
        if (($f = $this->logFile($name)) === null) {
            return $this->logs();
        }
        $limit = 45 * 1048576;
        if (filesize($f) <= $limit) {
            return $this->sendFile($this->input['chat'], curl_file_create($f));
        }
        $gz = tempnam(sys_get_temp_dir(), 'log');
        foreach ([0, max(0, filesize($f) - 4 * $limit)] as $from) {
            $in  = fopen($f, 'r');
            $out = gzopen($gz, 'wb6');
            fseek($in, $from);
            if ($from > 0) {
                fgets($in); // from the start of a line
            }
            while (!feof($in)) {
                gzwrite($out, (string) fread($in, 1048576));
            }
            fclose($in);
            gzclose($out);
            clearstatcache();
            if (filesize($gz) <= $limit) {
                break;
            }
        }
        $this->sendFile($this->input['chat'], curl_file_create($gz, 'application/gzip', basename($f) . ($from > 0 ? '.tail' : '') . '.gz'), $from > 0 ? 'the last part of the log' : false);
        @unlink($gz);
    }

    public function clearLog($name)
    {
        if (($f = $this->logFile($name)) !== null) {
            file_put_contents($f, '');
            foreach ($this->logCopies(basename($f)) as $c) {
                @unlink($c);
            }
        }
        $this->logs();
    }

    public function cleanLog()
    {
        foreach (scandir('/logs/') as $v) {
            // the listed logs only: not . / .. or service files like .warp_status
            if ($this->logFile($v) !== null) {
                if (preg_match('~\.(\d+|\d+\.gz)$~', $v)) {
                    @unlink("/logs/$v");
                } else {
                    file_put_contents("/logs/$v", '');
                }
            }
        }
        $this->logs();
    }
}
