<?php

// Routing lists (PAC menu): direct, block, WARP, rule sets: methods of class Bot (app/bot.php)
trait BotLists
{
    public function importList($type)
    {
        $this->prompt($this->i18n('send the export file:'), $this->i18n('send the export file:'), 'importListFile', [$type]);
    }

    public function importListFile($message, $type)
    {
        $f = $this->downloadInput(5 * 1048576);
        if ($f === null) {
            return $this->backXtlsList($type);
        }
        $list = [];
        foreach (explode("\n", $f) as $v) {
            if (!empty($s = trim($v))) {
                $t = explode(';', $s);
                if ($type != 'rulessetlist' || preg_match('~^.+:.+:https?://.+~', $t[0])) {
                    $list[$t[0]] = (bool) ($t[1] ?? false);
                }
            }
        }
        // a file without entries (wrong file, wrong list) changes nothing
        if (!$list) {
            $this->send($this->input['chat'], 'no entries in the file: the list stays as it is');
            return $this->backXtlsList($type);
        }
        $p = $this->getPacConf();
        $p[$type] = $list;
        $this->setPacConf($p);
        $this->backXtlsList($type);
    }

    public function include($type)
    {
        if ($type == 'rulessetlist') {
            $this->prompt($this->i18n('prompt rulesset'), 'outbound[:behavior]:time:URL', 'addInclude', [$type]);
        } else {
            $this->prompt($this->i18n('list separated by commas'), $this->i18n('ph: list separated by commas'), 'addInclude', [$type]);
        }
    }

    public function addInclude(string $domains, $type)
    {
        if ($type == 'rulessetlist' && !preg_match('~^.+:.+:https?://.+~', $domains)) {
            $this->send($this->input['from'], 'wrong pattern, enter [direct|block|proxy|custom outbound]:time:URL');
            return;
        }
        $domains = explode(',', $domains);
        $domains = array_filter($domains, fn($x) => !empty(trim($x)));
        if (!empty($domains)) {
            $conf  = $this->getPacConf();
            $wrong = [];
            foreach ($domains as $k => $v) {
                $v = trim($v);
                if (in_array($type, ['white', 'deny'])) {
                    if (!$this->validIpOrCidr($v)) {
                        $wrong[] = $v;
                        continue;
                    }
                    $conf[$type][] = $v;
                } elseif ($type == 'rulessetlist' || $this->validIpOrCidr($v)) {
                    $conf[$type][$v] = true;
                } elseif (($a = idn_to_ascii($v)) === false || $a === '') {
                    // not a name idn_to_ascii can convert: told, not added as ""
                    $wrong[] = $v;
                } else {
                    $conf[$type][$a] = true;
                }
            }
            if ($wrong) {
                $this->send($this->input['chat'], 'not added: ' . htmlspecialchars(implode(', ', $wrong)));
            }
            $conf[$type] ??= [];
            ksort($conf[$type]);
            $this->setPacConf($conf);
            $page = (int) floor(array_search($v, array_keys($conf[$type])) / $this->limit);
        }
        $page = $page ?: -2;
        $this->backXtlsList($type, $page);
    }

    public function backXtlsList($type, $page = 0)
    {
        switch ($type) {
            case 'includelist':
                $this->pacMenu($page);
                break;
            case 'blocklist':
                $this->xrayUpdateRules();
                $this->xtlsblock($page);
                break;
            case 'warplist':
                $this->xrayUpdateRules();
                $this->xtlswarp($page);
                break;
            case 'rulessetlist':
                $this->xtlsrulesset($page);
                break;
            case 'white':
            case 'deny':
                $this->syncDeny();
                $this->denyList($page, $type == 'white' ? 1 : 0);
                break;
        }
    }

    public function pacMenu($page = 0)
    {
        // the domain list goes into the subscriptions (~pac~ in templates)
        $text = $this->i18n('Menu') . ' -> pac';
        $data = $this->listPac('includelist', $page, 'pacMenu')[0];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function deleteYes($type)
    {
        $c = $this->getPacConf();
        unset($c[$type]);
        $this->setPacConf($c);
        switch ($type) {
            case 'includelist':
                $this->pacMenu();
                break;
            case 'blocklist':
                $this->xtlsblock();
                break;
            case 'warplist':
                $this->xtlswarp();
                break;
            case 'rulessetlist':
                $this->xtlsrulesset();
                break;
        }
    }

    public function deleteAll($type)
    {
        switch ($type) {
            case 'includelist':
                $dir = 'PAC';
                break;
            case 'warplist':
                $dir = 'WARP';
                break;
            case 'blocklist':
                $dir = 'BLOCK';
                break;
            case 'rulessetlist':
                $dir = 'rulesset';
                break;
        }
        $text   = <<<text
                {$this->i18n('Menu')} -> $dir -> {$this->i18n('delete all')}
                text;
        $data[] = [
            [
                'text'          => $this->i18n('yes'),
                'callback_data' => "/deleteYes $type",
            ],
        ];
        switch ($type) {
            case 'includelist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/pacMenu 0",
                    ],
                ];
                break;
            case 'warplist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlswarp",
                    ],
                ];
                break;
            case 'blocklist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlsblock",
                    ],
                ];
                break;
            case 'rulessetlist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlsrulesset",
                    ],
                ];
                break;
        }
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function exportList($type)
    {
        $domains = $this->getPacConf()[$type];
        if (!empty($domains)) {
            foreach ($domains as $k => $v) {
                $text .= "$k;$v\n";
            }
            $this->sendFile(
                $this->input['chat'],
                new CURLStringFile($text, "$type.csv", 'application/csv'),
                to: $this->input['message_id'],
            );
        }
    }





    public function xtlsblock($page = 0)
    {
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> ' . $this->i18n('block list');

        [$data] = $this->listPac('blocklist', $page, 'xtlsblock');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function xtlswarp($page = 0)
    {
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> ' . $this->i18n('warp list');

        [$data] = $this->listPac('warplist', $page, 'xtlswarp');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }


    public function xtlsrulesset($page = 0)
    {
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> ' . $this->i18n('rulesset list');

        [$data, $tmp] = $this->listPac('rulessetlist', $page, 'xtlsrulesset', 1);
        $text = array_merge($text, $tmp ?: []);
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function listPac($type, $page, $menu, $basename = false)
    {
        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/include $type",
            ],
        ];
        $domains = $this->getPacConf()[$type];
        if (!empty($domains)) {
            $all     = (int) ceil(count($domains) / $this->limit);
            $page    = min($page, $all - 1);
            $page    = $page < 0 ? $all - 1 : $page;
            $domains = array_slice($domains, $page * $this->limit, $this->limit, true);
            $i = 0;
            foreach ($domains as $k => $v) {
                if ($type == 'rulessetlist') {
                    $text[] = "<blockquote><code>" . htmlspecialchars((string) $k) . "</code></blockquote>";
                }
                $data[] = [
                    [
                        'text'          => $this->i18n($v ? 'on' : 'off') . ' ' . ($basename ? basename($k) . ' ' : '') . ($type == 'rulessetlist' ? $k : idn_to_utf8($k)),
                        'callback_data' => "/change$type " . $this->shortId((string) $k) . " $page",
                    ],
                    [
                        'text'          => $this->i18n('delete'),
                        'callback_data' => "/delete$type " . $this->shortId((string) $k) . " $page",
                    ],
                ];
                $i++;
            }
            if ($all > 1) {
                $data[] = [
                    [
                        'text'          => '<<',
                        'callback_data' => "/$menu " . ($page - 1 >= 0 ? $page - 1 : $all - 1),
                    ],
                    [
                        'text'          => $page + 1,
                        'callback_data' => "/$menu $page",
                    ],
                    [
                        'text'          => '>>',
                        'callback_data' => "/$menu " . ($page < $all - 1 ? $page + 1 : 0),
                    ],
                ];
            }
            $data[] = [
                [
                    'text'          => $this->i18n('delete all'),
                    'callback_data' => "/deleteAll $type",
                ],
                [
                    'text'          => $this->i18n('export'),
                    'callback_data' => "/exportList $type",
                ],
                [
                    'text'          => $this->i18n('import'),
                    'callback_data' => "/importList $type",
                ],
            ];
        } else {
            $data[] = [
                [
                    'text'          => $this->i18n('import'),
                    'callback_data' => "/importList $type",
                ],
            ];
        }
        return [$data, $text ?? ''];
    }

    // $id: shortId() of the entry; an entry removed meanwhile changes nothing
    public function listPacChange($type, $action, $id, $page = 0)
    {
        $conf = $this->getPacConf();
        foreach ($conf[$type] ?? [] as $k => $v) {
            if ($id === $this->shortId((string) $k)) {
                switch ($action) {
                    case 'change':
                        $conf[$type][$k] = !$v;
                        break;
                    case 'delete':
                        unset($conf[$type][$k]);
                        break;
                }
                break;
            }
        }
        $this->setPacConf($conf);
        $this->backXtlsList($type, $page);
    }
}
