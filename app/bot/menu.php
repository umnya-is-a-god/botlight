<?php

// Main menu, settings menu, ports, mirror: methods of class Bot (app/bot.php)
trait BotMenu
{
    public function setLang($lang)
    {
        $conf = $this->getPacConf();
        $this->language = $conf['language'] = $lang;
        $this->setPacConf($conf);
        $this->menu('config');
    }



    public function enterPage()
    {
        $this->prompt($this->i18n('enter limit on page'), $this->i18n('enter limit on page'), 'setPage');
    }

    public function setPage($text) {
        if (!preg_match('~^\d{1,3}$~D', $text = trim((string) $text)) || $text < 1 || $text > 100) {
            $this->send($this->input['chat'], 'wrong number: 1-100');
            return;
        }
        $c = $this->getPacConf();
        $c['limitpage'] = (int) $text;
        $this->setPacConf($c);
        // the polling process keeps one Bot object: apply without a restart
        $this->limit = $c['limitpage'];
        $this->menu('config');
    }

    /**
     * Published ports the admin switched on (AdGuard DoT 853, dnstt 53/udp).
     * Only these flags are written from here; the host builds the compose
     * file from them (scripts/ports.sh), so the bot never writes Docker config.
     */
    public function portSwitches(): array
    {
        $r = array_fill_keys(array_keys($this->ports), false);
        foreach (@file('/update/ports', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
            if (preg_match('~^(\w+)=1$~', trim($l), $m) && array_key_exists($m[1], $r)) {
                $r[$m[1]] = true;
            }
        }
        return $r;
    }

    public function getPorts()
    {
        $s = $this->portSwitches();
        $r = [];
        foreach ($this->ports as $k => $v) {
            $r[$k] = [
                'port'   => explode('/', $v)[0],
                'enable' => $s[$k],
            ];
        }
        return $r;
    }

    // the services as the main menu shows them (SSH to each, AdGuard over HTTP)
    public function serviceStatus(): array
    {
        return [
            'time'    => time(),
            'xray'    => (bool) $this->ssh('pgrep xray', 'xr'),
            'ocserv'  => (bool) $this->ssh('pgrep ocserv', 'oc'),
            'adguard' => $this->adguardUp(),
            'dnstt'   => (bool) $this->ssh('pgrep dnstt', 'dnstt'),
        ];
    }

    // cron, once a minute: the menu opens without the round trips
    public function statusCache()
    {
        if (!empty($this->time_status) && time() - $this->time_status < 60) {
            return;
        }
        $this->time_status = time();
        bot_write_json(BOT_DATA . '/status.json', $this->serviceStatus());
    }

    // the cron loop's last look if under 3 minutes old; null: the loop is not running
    public function cachedStatus(): ?array
    {
        $f = BOT_DATA . '/status.json';
        $s = is_file($f) ? json_decode((string) @file_get_contents($f), true) : null;
        return is_array($s) && time() - (int) ($s['time'] ?? 0) < 180 ? $s : null;
    }

    public function menu($type = false, $arg = false, $return = false)
    {
        $conf   = $this->getPacConf();
        $domain = ($conf['domain'] ?? null) ?: $this->ip;
        $hash   = $this->getHashBot();
        if ($type == false) {
            ['behind' => $update, 'branch' => $branch] = $this->gitState();
            // what the cron loop saw a moment ago; looked at now only when
            // the loop is not running
            $st     = $this->cachedStatus();
            $cronOn = $st !== null;
            $st   ??= $this->serviceStatus();
            $backup = '';
            if (!empty($conf['backup'])) {
                $b      = array_map('trim', explode('/', $conf['backup'], 2));
                $backup = $this->backupSchedule($conf['backup']) ? "{$b[0]} start / {$b[1]} period" : htmlspecialchars($conf['backup']) . ' - wrong format';
            }
            $cron   = $this->dontshowcron ? '' : $this->i18n($cronOn ? 'on' : 'off') . ' cron';
            $main[] = 'v' . getenv('VER') . " $branch" . ($update ? ' (have updates)' : '');

            if (!empty($conf['domain'])) {
                $main[] = '';
                if (!empty($conf['domain'])) {
                    $main[] = "<blockquote>";
                    array_push($main, ...$this->domainLines());
                    $main[] = "</blockquote>";
                } else {
                    $main[] = $this->i18n('domain explain');
                }
            }


            $ports  = $this->getPorts();
            $main[] = '';

            // DNSTT is opened with /dnstt; its status shows once it is set up
            $dnstt   = !empty($conf['dnsttDomain']) || !empty($ports['dnstt']['enable']);
            $status  = [
                $this->i18n(!empty($st['xray']) ? 'on' : 'off') . ' ' . $this->i18n('xray'),
                $this->i18n(!empty($st['ocserv']) ? 'on' : 'off') . ' ' . $this->i18n('ocserv'),
                $this->i18n(!empty($st['adguard']) ? 'on' : 'off') . ' ' . $this->i18n('ad_title'),
            ];
            $portcol = [
                $this->i18n('on') . ' 443',
                $this->i18n('on') . ' 443',
                $this->i18n(!empty($ports['ad']['enable']) ? 'on' : 'off') . (!empty($ports['ad']['enable']) ? ' ' . $ports['ad']['port'] : ' port is closed'),
            ];
            if ($dnstt) {
                $status[]  = $this->i18n(!empty($st['dnstt']) ? 'on' : 'off') . ' ' . $this->i18n('dnstt');
                $portcol[] = $this->i18n(!empty($ports['dnstt']['enable']) ? 'on' : 'off') . (!empty($ports['dnstt']['enable']) ? ' ' . $ports['dnstt']['port'] : ' port is closed');
            }
            // on, plus (WARP+) or off
            $status[]  = $this->i18n($this->cachedWarpStatus() === 'off' ? 'off' : 'on') . ' ' . $this->i18n('warp');
            $portcol[] = '';
            if (!empty($conf['bridge'])) {
                $status[]  = $this->i18n('on') . ' bridge';
                $portcol[] = $conf['bridge'];
            }
            $main[] = '<code>';
            $main[] = $this->alignColumns([$status, $portcol]);
            $main[] = '';
            $main[] = $this->alignColumns([
                [
                    $this->i18n($this->backupSchedule($conf['backup'] ?? '') ? 'on' : 'off') . ' autobackup',
                    $this->i18n(!empty($conf['autoupdate']) ? 'on' : 'off') . ' autoupdate',
                    $this->i18n(!empty($conf['autoscan']) ? 'on' : 'off') . ' autoscan',
                ],
                [
                    $this->i18n(!empty($conf['autodeny']) ? 'on' : 'off') . ' autoblock' . (!empty($conf['deny']) ? ': ' . count($conf['deny']) : ''),
                    $this->i18n(!empty($conf['reset_monthly']) ? 'on' : 'off') . ' autoreset',
                    $cron,
                ],
            ]);
            $main[] = '</code>';

        }
        $menu   = [
            'main' => [
                'text' => implode("\n", $main ?? []),
                'data' => array_merge(
                    [
                        [
                            [
                                'text'          => $this->i18n('xray'),
                                'callback_data' => "/xray",
                            ],
                            [
                                'text'          => $this->i18n('ocserv'),
                                'callback_data' => "/menu oc",
                            ],
                        ],
                        [
                            [
                                'text'          => $this->i18n('ad_title'),
                                'callback_data' => "/menu adguard",
                            ],
                            [
                                'text'          => $this->i18n('pac'),
                                'callback_data' => "/pacMenu 0",
                            ],
                        ],
                    ],
                    [
                        // DNSTT has no button here: it is opened with /dnstt
                        [
                            [
                                'text'          => $this->i18n('warp'),
                                'callback_data' => "/warp",
                            ],
                            [
                                'text'          => $this->i18n('config'),
                                'callback_data' => "/menu config",
                            ],
                        ],
                    ],
                )
            ],
            'pac'          => $type == 'pac'     ? $this->pacMenu((int) $arg)              : false,
            'adguard'      => $type == 'adguard' ? $this->adguardMenu()                    : false,
            'config'       => $type == 'config'  ? $this->configMenu()                     : false,
            'lang'         => $type == 'lang'    ? $this->menuLang()                       : false,
            'oc'           => $type == 'oc'      ? $this->ocMenu()                         : false,
            'mirror'       => $type == 'mirror'  ? $this->mirrorMenu()                     : false,
            'update'       => $type == 'update'  ? $this->updatebot()                      : false,
        ];

        $text = $menu[$type ?: 'main']['text'] ?? '';
        $data = $menu[$type ?: 'main']['data'] ?? [];

        if (empty($type) && $update) {
            array_unshift($data, [
                [
                    'text'          => $this->i18n('changelog'),
                    'callback_data' => "/changelog",
                ],
                [
                    'text'          => $this->i18n('update bot'),
                    'callback_data' => "/applyupdatebot",
                ],
            ]);
        }

        if ($return) {
            return [$text, $data];
        }

        if (!empty($this->input['callback_id'])) {
            $this->update(
                $this->input['chat'],
                $this->input['message_id'],
                $text,
                $data ?: false,
            );
        } else {
            $this->send(
                $this->input['chat'],
                $text,
                $this->input['message_id'],
                $data ?: false,
            );
        }
    }

    public function mirrorMenu()
    {
        $ports  = $this->mirrorPorts();
        $bridge = $this->getPacConf()['bridge'] ?? '';
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('Mirror');
        $text[] = "<pre>client -> mirror (another server) -> this server</pre>";
        $text[] = 'The mirror forwards this server\'s open ports: tcp ' . implode(' ', $ports['tcp']) . ', udp ' . implode(' ', $ports['udp']) . '. Download the script and run it on the mirror (again after opening or closing a port in Settings -> Ports):';
        $text[] = '<code>sudo bash socat.sh</code> — to this server over IPv4';
        $text[] = '<code>sudo bash socat.sh IPv6</code> — over IPv6 (this server\'s IPv6 address)';
        $text[] = '<code>sudo bash socat.sh remove</code> — remove';
        $text[] = '';
        $text[] = '• Point the domain (and the OpenConnect subdomain) to the mirror: links, subscriptions and certificates keep working through it. Cloudflare: DNS only (grey cloud).';
        $text[] = '• Set the bridge IP below: the IP limit is turned off (all clients come from that IP) and the IP is added to the ignorelist, so the IP analysis does not block the mirror.';
        $text[] = '';
        $text[] = 'bridge IP: ' . ($bridge !== '' ? "<code>$bridge</code>" : 'not set');
        $data[] = [
            [
                'text'          => $this->i18n('download'),
                'callback_data' => "/getMirror",
            ],
            [
                'text'          => $this->i18n('bridge IP') . ': ' . ($bridge !== '' ? $this->i18n('on') . " $bridge" : $this->i18n('off')),
                'callback_data' => "/setBridge",
            ],
        ];
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

    public function bridgePrompt()
    {
        $this->prompt($this->i18n('prompt bridge'), $this->i18n('bridge IP'), 'setBridge');
    }

    /**
     * Bridge mode: clients come through the mirror, all from its IP. The IP
     * limit is off (it cannot tell users apart) and the bridge IP is in the
     * ignorelist (the IP analysis would take it for a scanner).
     */
    public function setBridge($text)
    {
        $ip  = trim((string) $text);
        $pac = $this->getPacConf();
        $old = $pac['bridge'] ?? '';
        if ($ip !== '-' && !filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->send($this->input['chat'], 'wrong IP');
            return $this->menu('mirror');
        }
        $white = array_values(array_filter($pac['white'] ?? [], fn($v) => $v !== $old));
        if ($ip === '-') {
            unset($pac['bridge']);
        } else {
            $pac['bridge'] = $ip;
            $white[]       = $ip;
            $restart       = !empty($pac['ip_limit']);
            unset($pac['ip_limit'], $pac['ip_count']);
        }
        $pac['white'] = array_values(array_unique($white));
        $this->setPacConf($pac);
        $this->syncDeny();
        if (!empty($restart)) {
            // the access log goes off with the limit
            $this->restartXray($this->getXray());
            @file_put_contents('/logs/xray', '');
        }
        $this->menu('mirror');
    }

    // ports the server publishes (docker-compose.yml and the port switches)
    public function mirrorPorts(): array
    {
        $p   = $this->getPorts();
        $tcp = ['80', '443'];
        $udp = ['443'];
        if (!empty($p['ad']['enable'])) {
            $tcp[] = $p['ad']['port'];
        }
        if (!empty($p['dnstt']['enable'])) {
            $udp[] = $p['dnstt']['port'];
        }
        return ['tcp' => $tcp, 'udp' => $udp];
    }

    public function getMirror()
    {
        // socat targets an IPv4 address here
        if (!filter_var($this->ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->answer($this->input['callback_id'], 'the server IPv4 address is not known (IP in .env)', true);
        }
        $ports = $this->mirrorPorts();
        $t     = str_replace(
            ['~ip~', '~tcp~', '~udp~'],
            [$this->ip, implode(' ', $ports['tcp']), implode(' ', $ports['udp'])],
            file_get_contents('/mirror/start_socat.sh')
        );
        $this->sendFile($this->input['from'], new CURLStringFile($t, 'socat.sh', 'application/x-sh'));
    }

    public function menuLang()
    {
        $data = [];
        $lang = [];
        foreach ($this->i18n as $k => $v) {
            $lang = array_merge($lang, array_keys($v));
        }
        $lang = array_unique($lang);
        foreach ($lang as $v) {
            if ($v != $this->language) {
                $data[] = [
                    [
                        'text'          => $v,
                        'callback_data' => "/lang $v",
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        return [
            'text' => $this->i18n('Language'),
            'data' => $data,
        ];
    }

    public function configMenu()
    {
        $conf = $this->getPacConf();
        if (!empty($conf['domain'])) {
            $text[] = "<blockquote>";
            array_push($text, ...$this->domainLines());
            $text[] = "</blockquote>";
        } else {
            $text[] = $this->i18n('domain explain');
        }

        $data = [
            [
                [
                    'text'          => !empty($conf['domain']) ? "{$this->i18n('delete')} {$conf['domain']}" : $this->i18n('install domain'),
                    'callback_data' => !empty($conf['domain']) ? '/deldomain' : '/domain',
                ],
                [
                    'text'          => $this->i18n('nip.io'),
                    'callback_data' => '/addNipdomain',
                ],
            ],
        ];
        if (!empty($conf['domain'])) {
            if ($cert = $this->nginxGetTypeCert()) {
                switch ($cert) {
                    case 'letsencrypt':
                        $data[] = [
                            [
                                'text'          => $this->i18n('renew SSL'),
                                'callback_data' => "/setSSL letsencrypt",
                            ],
                            [
                                'text'          => $this->i18n('delete SSL'),
                                'callback_data' => "/deletessl",
                            ],
                        ];
                        break;
                    case 'self':
                        $data[] = [
                            [
                                'text'          => $this->i18n('delete SSL'),
                                'callback_data' => "/deletessl",
                            ],
                        ];
                        break;
                }
            } else {
                $data[] = [
                    [
                        'text'          => $this->i18n('Letsencrypt SSL'),
                        'callback_data' => "/setSSL letsencrypt",
                    ],
                    [
                        'text'          => $this->i18n('Self SSL'),
                        'callback_data' => "/selfssl",
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('Ports'),
                'callback_data' => "/ports",
            ],
            [
                'text'          => $this->i18n('logs'),
                'callback_data' => "/logs",
            ],
            [
                'text'          => $this->i18n('IP ban'),
                'callback_data' => "/ipMenu",
            ],
        ];

        $data[] = [
            [
                'text'          => $this->i18n('lang'),
                'callback_data' => "/menu lang",
            ],
            [
                'text'          => "{$this->i18n('page')}: " . (($conf['limitpage'] ?? null) ?: 5),
                'callback_data' => "/enterPage",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('export'),
                'callback_data' => "/export",
            ],
            [
                'text'          => $this->i18n('import'),
                'callback_data' => "/import",
            ],
            [
                // backups are only sent encrypted with this password
                'text'          => '🔐 ' . $this->i18n($this->backupKey() ? 'on' : 'off'),
                'callback_data' => "/backupPassword",
            ],
        ];
        $backup = '';
        if (!empty($conf['backup'])) {
            $b      = array_map('trim', explode('/', $conf['backup'], 2));
            $backup = $this->backupSchedule($conf['backup']) ? "{$b[0]} start / {$b[1]} period" : $this->i18n('off') . " {$conf['backup']} - wrong format";
        }
        $data[] = [
            [
                'text'          => $this->i18n('backup') . ': ' . ($backup ?: $this->i18n('off')),
                'callback_data' => "/backup",
            ],
            [
                'text'          => $this->i18n('auto update') . ': ' .  $this->i18n(!empty($conf['autoupdate']) ? 'on' : 'off'),
                'callback_data' => "/autoupdate",
            ],
        ];
        // cover page at the site root ("fake html"); the monthly reset of
        // the Xray and OpenConnect traffic
        $fake   = is_file(BOT_DATA . '/www/override.html');
        $data[] = [
            [
                'text'          => $this->i18n('fake html') . ': ' . $this->i18n($fake ? 'on' : 'off'),
                'callback_data' => '/addOverrideHtml',
            ],
            [
                'text'          => $this->i18n('auto reset stats') . ': ' . $this->i18n(!empty($conf['reset_monthly']) ? 'on' : 'off'),
                'callback_data' => '/switchMonthlyStats',
            ],
        ];
        if ($fake) {
            $data[] = [
                [
                    'text'          => $this->i18n('delete') . ' ' . $this->i18n('fake html'),
                    'callback_data' => '/delOverrideHtml',
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('manage updates'),
                'callback_data' => "/menu update",
            ],
            [
                'text'          => $this->i18n('restart'),
                'callback_data' => "/restart",
            ],
            [
                // new images on GitHub (scripts/images.sh check): how many
                'text'          => $this->i18n('update images') . (($n = count($this->newImages())) ? " 🆕 $n" : ''),
                'callback_data' => "/rebuild",
            ],
        ];
        $data[] = [
            [
                'text'          => "{$this->i18n('add')} {$this->i18n('admin')}",
                'callback_data' => "/addadmin",
            ],
        ];
        $admins = $this->adminConfig();
        foreach ($admins['admin'] as $k => $v) {
            $data[] = [
                [
                    'text'          => ($k === 0 ? '👑 ' : '') . $this->adminLabel($admins, $v),
                    'callback_data' => "/adminCard $v",
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

    public function ports()
    {
        $text[] = $this->i18n('config') . ' -> ' . $this->i18n('Ports');
        $c      = $this->portSwitches();
        $pac    = $this->getPacConf();
        $data   = [
            [[
                'text'          => $this->i18n(!empty($c['ad']) ? 'on' : 'off') . ' 853 AdguardHome DoT',
                'callback_data' => "/hidePort ad",
            ]],
            [[
                'text'          => $this->i18n(!empty($c['dnstt']) ? 'on' : 'off') . ' 53 dnstt',
                'callback_data' => "/hidePort dnstt",
            ]],
        ];
        if (!empty($pac['restart'])) {
            $data[] = [
                [
                    'text'          => $this->i18n('restart'),
                    'callback_data' => "/restart",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function hidePort($container)
    {
        $s = $this->portSwitches();
        if (array_key_exists($container, $s)) {
            $s[$container] = !$s[$container];
            file_put_contents('/update/ports', implode('', array_map(fn($k) => "$k=1\n", array_keys(array_filter($s)))));
            $pac = $this->getPacConf();
            $pac['restart'] = 1;
            $this->setPacConf($pac);
        }
        $this->ports();
    }
}
