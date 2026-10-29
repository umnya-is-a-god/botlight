<?php

// Subscriptions (sing-box, mihomo, Happ) and their templates: methods of class Bot (app/bot.php)
trait BotSubscription
{
    public function templateAdd($type)
    {
        $this->prompt($this->i18n('send the template file:'), $this->i18n('send the template file:'), 'addTemplate', [$type]);
    }

    public function templateCopy($type)
    {
        $this->prompt($this->i18n('send the template name'), $this->i18n('send the template name'), 'copyTemplate', [$type]);
    }

    /**
     * Template names go into button data (base64, Telegram allows 64 bytes
     * per button): short, plain characters, and not the built-in "origin".
     */
    public function validTemplateName($name): bool
    {
        return is_string($name) && $name !== 'origin' && strlen($name) <= 24
            && (bool) preg_match('~^[\p{L}\p{N}][\p{L}\p{N} ._-]*$~uD', $name);
    }

    public function addTemplate($n, $type)
    {
        if (!$this->validTemplateName($name = trim((string) $this->input['caption']))) {
            $this->send($this->input['chat'], 'name in the file caption: up to 24 bytes, letters, digits, space . _ -, not "origin"');
            return;
        }
        $f = $this->downloadInput(1048576);
        if ($f === null) {
            return;
        }
        $json = json_decode($f, true);
        if (!is_array($json)) {
            $this->send($this->input['chat'], 'wrong format');
            return;
        }
        $t = $this->getTemplates($type);
        $t[$name] = $json;
        $this->saveTemplates($type, $t);
        $this->templates($type);
    }

    /**
     * Named sing-box / mihomo templates (/data/templates/<type>.json). The
     * folder belongs to the web pools' group: the Mini App editor saves
     * into it without access to the other settings.
     */
    public function getTemplates(string $type): array
    {
        $f = BOT_DATA . "/templates/$type.json";
        return is_file($f) ? bot_read_json($f) : [];
    }

    public function saveTemplates(string $type, array $t)
    {
        bot_write_json(BOT_DATA . "/templates/$type.json", $t, 0660, BOT_GID_WEB);
    }

    // the built-in template: as edited in the Mini App, else config/<type>.json
    public function originTemplate(string $type): array
    {
        $f = BOT_DATA . "/templates/$type.origin.json";
        return bot_read_json(is_file($f) ? $f : "/config/$type.json");
    }

    public function saveTemplate($name, $type, $json)
    {
        if (!in_array($type, ['sing', 'clash'], true)) {
            return ['status' => false, 'message' => 'wrong template type'];
        }
        if ($name !== 'origin' && !$this->validTemplateName($name)) {
            return ['status' => false, 'message' => 'wrong template name'];
        }
        if (!is_array(json_decode($json, true))) {
            return [
                'status'  => false,
                'message' => 'wrong format',
            ];
        }
        switch ($name) {
            case 'origin':
                bot_write_json(BOT_DATA . "/templates/$type.origin.json", json_decode($json, true), 0660, BOT_GID_WEB);
                break;

            default:
                bot_lock(BOT_DATA . "/templates/$type.json", function () use ($type, $name, $json) {
                    $t = $this->getTemplates($type);
                    $t[$name] = json_decode($json, true);
                    $this->saveTemplates($type, $t);
                });
                break;
        }
        return [
            'status' => true,
        ];
    }

    public function delTemplate($type, $name)
    {
        $t = $this->getTemplates($type);
        unset($t[base64_decode((string) $name)]);
        $this->saveTemplates($type, $t);
        $this->templates($type);
    }

    public function copyTemplate($name, $type)
    {
        if (!$this->validTemplateName($name = trim((string) $name))) {
            $this->send($this->input['chat'], 'name: up to 24 bytes, letters, digits, space . _ -, not "origin"');
            return $this->templates($type);
        }
        $t = $this->getTemplates($type);
        $t[$name] = $this->originTemplate($type);
        $this->saveTemplates($type, $t);
        $this->templates($type);
    }

    public function downloadOrigin($type)
    {
        $f = new \CURLStringFile(json_encode($this->originTemplate($type), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), 'origin.json', 'application/json');
        $this->sendFile($this->input['chat'], $f);
    }

    public function downloadTemplate($type, $name)
    {
        $t = $this->getTemplates($type)[base64_decode((string) $name)] ?? null;
        if (!is_array($t)) {
            return $this->templates($type);
        }
        $f = new \CURLStringFile(json_encode($t, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), base64_decode($name) . '.json', 'application/json');
        $this->sendFile($this->input['chat'], $f);
    }

    public function defaultTemplate($type, $name)
    {
        $pac = $this->getPacConf();
        if (!empty($name)) {
            $pac["default{$type}template"] = $name;
        } else {
            unset($pac["default{$type}template"]);
        }
        $this->setPacConf($pac);
        $this->templates($type);
    }

    public function templates($type)
    {
        $pac    = $this->getPacConf();
        $pac["{$type}templates"] = $this->getTemplates($type);
        $domain = $this->getDomain();
        $hash   = $this->getHashBot();
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . ' -> ' . $this->i18n("$type templates");
        $text[] = <<<TEXT
            <code>~outbound~</code>
            <code>~pac~</code>
            <code>~block~</code>
            <code>~warp~</code>
            <code>~dns~</code>
            <code>~dnspath~</code>
            <code>~uid~</code>
            <code>~domain~</code>
            <code>~directdomain~</code>
            <code>~cdndomain~</code>
            <code>~short_id~</code>
            <code>~email~</code>
            <code>~public_key~</code>
            <code>~server_name~</code>
            <code>~ip~</code>
            TEXT;
        $templates = $pac["{$type}templates"];

        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/templateAdd $type",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('origin'),
                'web_app' => ['url' => "https://$domain/webapp{$this->getAdminHash()}/editor?ty=$type"],
            ],
            [
                'text'          => $this->i18n('download'),
                'callback_data' => "/downloadOrigin $type",
            ],
            [
                'text'          => $this->i18n('copy'),
                'callback_data' => "/templateCopy $type",
            ],
            [
                'text'          => $this->i18n(!empty($pac["default{$type}template"]) && !empty($pac["{$type}templates"][base64_decode($pac["default{$type}template"])]) ? 'off' : 'on'),
                'callback_data' => "/defaultTemplate $type",
            ],
        ];
        foreach ($templates ?: [] as $k => $v) {
            $data[] = [
                [
                    'text'          => $k,
                    'web_app' => ['url' => "https://$domain/webapp{$this->getAdminHash()}/editor?ty=$type&te=" . urlencode($k)],
                ],
                [
                    'text'          => $this->i18n('download'),
                    'callback_data' => "/downloadTemplate $type " . base64_encode($k),
                ],
                [
                    'text'          => $this->i18n('delete'),
                    'callback_data' => "/delTemplate $type " . base64_encode($k),
                ],
                [
                    'text'          => $this->i18n(($pac["default{$type}template"] ?? null) == base64_encode($k) ? 'on' : 'off'),
                    'callback_data' => "/defaultTemplate $type " . base64_encode($k),
                ],
            ];
        }

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

    /**
     * The user's template: $tid 'd' the default, 'o' the built-in one, or
     * the id of a named template (templateId). Stored as before: base64 of
     * the name.
     */
    public function choiceTemplate($type, $i, $tid)
    {
        $c = $this->getXray();
        if (!isset($c['inbounds'][0]['settings']['clients'][$i])) {
            return $this->xray();
        }
        $name = $tid === 'o' ? 'origin' : null;
        foreach (array_keys($this->getTemplates($type)) as $k) {
            if ($tid === $this->templateId((string) $k)) {
                $name = (string) $k;
            }
        }
        if ($name !== null) {
            $c['inbounds'][0]['settings']['clients'][$i]["{$type}template"] = base64_encode($name);
        } elseif ($tid === 'd') {
            unset($c['inbounds'][0]['settings']['clients'][$i]["{$type}template"]);
        } else {
            // the template was deleted meanwhile
            return $this->templateUser($type, $i);
        }
        $this->saveXray($c);
        $this->userXr($i);
    }

    // short id of a template name for button data (64 bytes at most)
    public function templateId(string $name): string
    {
        return substr(hash('sha256', $name), 0, 10);
    }

    public function templateUser($type, $i)
    {
        $c         = $this->getXray();
        $pac       = $this->getPacConf();
        $pac["{$type}templates"] = $this->getTemplates($type);
        $text[]    = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . " -> {$c['inbounds'][0]['settings']['clients'][$i]['email']}\n";
        $templates = $pac["{$type}templates"];
        $uid       = $this->xrUid($c['inbounds'][0]['settings']['clients'][$i] ?? []);
        $t         = $type == 'sing' ? 's' : 'c';
        $data[]    = [
            [
                'text'          => $this->i18n('default'),
                'callback_data' => "/chT $t $uid d",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('origin'),
                'callback_data' => "/chT $t $uid o",
            ],
        ];
        foreach ($templates ?: [] as $k => $v) {
            $data[] = [
                [
                    'text'          => $k,
                    'callback_data' => "/chT $t $uid " . $this->templateId((string) $k),
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/userXr $uid",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function getDomain($cdn = false)
    {
        $c = $this->getPacConf();
        if ($cdn && !empty($c['linkdomain'])) {
            return $c['linkdomain'];
        }
        return ($c['domain'] ?? null) ?: $this->ip;
    }

    public function subscription()
    {
        switch ($_GET['t']) {
            case 'si':
                $type = 'sing';
                break;
            case 'cl':
                $type = 'clash';
                break;
            default:
                header('404', true, 404);
                exit;
        }
        // the user first: nothing else is read for an unknown or disabled one
        $xr     = $this->getXray();
        $client = null;
        $sid = is_string($_GET['s'] ?? null) ? $_GET['s'] : '';
        foreach ($xr['inbounds'][0]['settings']['clients'] as $v) {
            if ($sid !== '' && hash_equals((string) $v['id'], $sid)) {
                $client = $v;
                break;
            }
        }
        if ($client === null || !empty($client['off'])) {
            header('404', true, 404);
            exit;
        }
        $template = base64_decode((string) ($client["{$type}template"] ?? ''));
        $uid      = $client['id'];
        $email    = $client['email'];
        $pac    = $this->getPacConf();
        $pac["{$type}templates"] = $this->getTemplates($type);
        if ($type == 'sing' && ($pac['transport'] ?? '') == 'xhttp') {
            // sing-box has no XHTTP transport: an error, not a config it rejects
            header('Content-Type: text/plain', true, 404);
            echo 'sing-box does not support the XHTTP transport';
            exit;
        }
        $domain = $this->requestDomain($pac);
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        if (!empty($_GET['r'])) {
            $si = $this->subLink($scheme, $domain, 'si', $uid);
            $cl = $this->subLink($scheme, $domain, 'cl', $uid);
            switch ($_GET['r']) {
                case 'si':
                    header("Location: sing-box://import-remote-profile/?url=$si");
                    exit;
                case 'c':
                    header("Location: clash://install-config/?url=$cl&overwrite=no&name=" . rawurlencode((string) $email));
                    exit;
            }
        }
        switch (true) {
            case !empty($template) && $template == 'origin':
            case empty($template) && empty($pac["default{$type}template"]):
            case empty($template) && empty($pac["{$type}templates"][base64_decode($pac["default{$type}template"])]):
            case !empty($template) && empty($pac["{$type}templates"][$template]):
                $c = $this->originTemplate($type);
                break;
            case !empty($template):
                $c = $pac["{$type}templates"][$template];
                break;

            default:
                $c = $pac["{$type}templates"][base64_decode($pac["default{$type}template"])];
                break;
        }

        $outbound = ($pac['outbound'] ?? null) ?: 'proxy';
        $c = json_decode($this->replaceTags(json_encode($c), [
            '~outbound~' => $outbound,
        ]), true);
        foreach ($c['outbounds'] ?? [] as $k => $v) {
            if (($v['tag'] ?? null) == $outbound) {
                $index = $k;
                break;
            }
        }
        if (!isset($index)) {
            foreach ($c['proxies'] ?? [] as $k => $v) {
                if (($v['name'] ?? null) == $outbound) {
                    $index = $k;
                    break;
                }
            }
        }
        if (!isset($index)) {
            // the template has no outbound/proxy with the main outbound tag
            error_log("subscription: template has no outbound \"$outbound\"");
            header('500', true, 500);
            exit;
        }

        switch ($_GET['t']) {
            case 'si':
                $c['outbounds'][$index]['uuid'] = '~uid~';
                switch ($pac['transport'] ?? '') {
                    case 'Reality':
                        unset($c['outbounds'][$index]["transport"]);
                        $c['outbounds'][$index]['flow']                         = 'xtls-rprx-vision';
                        $c['outbounds'][$index]['tls']['reality']['public_key'] = '~public_key~';
                        $c['outbounds'][$index]['tls']['server_name']           = '~server_name~';
                        $c['outbounds'][$index]['tls']['reality']['short_id']   = '~short_id~';
                        break;
                    case 'xhttp':
                        unset($c['outbounds'][$index]['flow']);
                        unset($c['outbounds'][$index]['tls']['reality']);

                        $c['outbounds'][$index]["transport"] = [
                            "type" => "xhttp",
                            "host" => "~domain~",
                            "mode" => "packet-up",
                            "path" => "/ws$hash",  // ← путь WS + hash
                            "xmux" => [
                                "max_concurrency"   => "16-32",
                                "c_max_reuse_times" => "0",
                                "h_max_request_times" => "600-900",
                                "h_max_reusable_secs" => "1800-3000",
                                "h_keep_alive_period" => 0
                            ]
                        ];

                        $c['outbounds'][$index]['tls'] = [
                            "enabled"     => true,
                            "insecure"    => false,
                            "server_name" => "~domain~",
                            "alpn"        => ["h2"]
                        ];
                        break;

                    default:
                        unset($c['outbounds'][$index]['tls']['reality']);
                        unset($c['outbounds'][$index]['flow']);
                        $c['outbounds'][$index]["transport"] = [
                            "type" => "ws",
                            "path" => "/ws$hash"
                        ];
                        $c['outbounds'][$index]['tls']['server_name'] = '~domain~';
                        break;
                }
                break;
            case 'cl':
                $c['proxies'][$index]['server'] = '~domain~';
                $c['proxies'][$index]['uuid']   = '~uid~';
                switch (true) {
                    case ($pac['transport'] ?? null) == 'Reality':
                        unset($c['proxies'][$index]["ws-opts"]);
                        unset($c['proxies'][$index]["skip-cert-verify"]);
                        $c['proxies'][$index]["network"]      = "tcp";
                        $c['proxies'][$index]['flow']         = 'xtls-rprx-vision';
                        $c['proxies'][$index]['servername']  = '~server_name~';
                        $c['proxies'][$index]['reality-opts'] = [
                            'public-key' => '~public_key~',
                            'short-id'   => '~short_id~',
                        ];
                        break;
                    case ($pac['transport'] ?? null) == 'xhttp':
                        unset($c['proxies'][$index]['ws-opts']);
                        unset($c['proxies'][$index]['flow']);
                        unset($c['proxies'][$index]['reality-opts']);

                        $c['proxies'][$index]['network']            = 'xhttp';
                        $c['proxies'][$index]['client-fingerprint'] = 'chrome';
                        $c['proxies'][$index]['tls']                = true;
                        $c['proxies'][$index]['alpn']               = ['h2'];
                        $c['proxies'][$index]['servername']         = '~domain~';
                        $c['proxies'][$index]['skip-cert-verify']   = false;

                        $c['proxies'][$index]['xhttp-opts'] = [
                            'host'                   => '~domain~',
                            'path'                   => "/ws$hash",
                            'mode'                   => 'packet-up',
                            'no-grpc-header'         => false,
                            'x-padding-bytes'        => '100-1000',
                            'sc-max-each-post-bytes' => 1000000,
                            'reuse-settings'         => [
                                'max-concurrency'     => '16-32',
                                'c-max-reuse-times'   => '0',
                                'h-max-request-times' => '600-900',
                                'h-max-reusable-secs' => '1800-3000',
                            ],
                        ];
                        break;

                    default:
                        unset($c['proxies'][$index]['flow']);
                        unset($c['proxies'][$index]['reality-opts']);
                        $c['proxies'][$index]["network"]          = "ws";
                        $c['proxies'][$index]["ws-opts"]['path']  = "/ws$hash";
                        $c['proxies'][$index]["skip-cert-verify"] = false;
                        $c['proxies'][$index]['servername']       = '~domain~';
                        break;
                }
                break;
        }
        $c = json_decode($this->replaceTags(json_encode($c), [
            '"~pac~"'        => json_encode(array_keys(array_filter(($pac['includelist'] ?? null) ?: []))),
            '"~block~"'      => json_encode(array_keys(array_filter(($pac['blocklist'] ?? null) ?: []))),
            '"~warp~"'       => json_encode(array_keys(array_filter(($pac['warplist'] ?? null) ?: []))),
            '~dns~'          => "https://$domain/dns-query$hash/$uid",
            '~dnspath~'      => "/dns-query$hash/$uid",
            '~uid~'          => $uid,
            '~domain~'       => $domain,
            '~directdomain~' => $pac['domain'],
            '~cdndomain~'    => $pac['linkdomain'] ?? '',
            '~short_id~'     => $xr['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0] ?? '',
            '~email~'        => $email,
            '~public_key~'   => $pac['xray'] ?? '',
            '~server_name~'  => $xr['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0] ?? '',
            '~ip~'           => $this->ip,
            '~outbound~'     => $outbound,
        ]), true);

        switch ($_GET['t']) {
            case 'si':
                $c['route'] = $this->addRuleSet($c['route']);
                $c['route'] = $this->createRuleSet($c['route'], $uid, $domain);
                $c          = $this->singHttpClients($c);
                if (!empty($c['route']['rules'])) {
                    foreach ($c['route']['rules'] as $k => $v) {
                        if (count($v) == 1 && array_key_exists('outbound', $v)) {
                            unset($c['route']['rules'][$k]);
                        }
                    }
                    $c['route']['rules'] = array_values($c['route']['rules']);
                }
                if (empty($c['route'])) {
                    unset($c['route']);
                }
                break;
            case 'cl':
                $c = $this->addClashRuleSet($c);
                if (!empty($c['rules'])) {
                    $c = $this->clashRules($c, $uid, $domain);
                    if (count($c['rules']) == 1) {
                        unset($c['rules']);
                    }
                }
                break;
        }
        if (($_GET['t'] ?? null) == 'cl') {
            header('Content-type: text/yaml');
            echo yaml_emit($c);
            return;
        }

        header('Content-type: application/json');
        // readable when the link is opened in a browser; apps do not care
        echo json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Subscription for Happ: the user's vless link (base64 list, as Xray
     * clients expect) and, when set in the Xray menu, a routing profile in
     * the "routing" header (https://www.happ.su/main/dev-docs/routing).
     * ?r=hp redirects to happ://add/<this subscription>.
     */
    public function happSubscription()
    {
        $pac = $this->getPacConf();
        $xr  = $this->getXray();
        $sid = is_string($_GET['s'] ?? null) ? $_GET['s'] : '';
        $i   = null;
        foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($sid !== '' && hash_equals((string) $v['id'], $sid)) {
                $i = empty($v['off']) ? $k : null;
                break;
            }
        }
        if ($i === null) {
            header('500', true, 500);
            exit;
        }
        if (($_GET['r'] ?? '') === 'hp') {
            $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
            $domain = $this->requestDomain($pac);
            header("Location: happ://add/$scheme://$domain/pac{$this->getHashBot()}?t=hp&s=$sid");
            exit;
        }
        if ($routing = $this->happRoutingLink($pac['happrouting'] ?? '')) {
            header("routing: $routing");
        }
        header('Content-Type: text/plain');
        echo base64_encode($this->linkXray($i) . "\n");
    }

    // happ://routing/add|onadd/<base64 of a JSON object>
    public function validHappRouting($link): bool
    {
        if (!is_string($link) || !preg_match('~^happ://routing/(?:on)?add/([A-Za-z0-9+/_-]+={0,2})$~D', $link, $m)) {
            return false;
        }
        $json = json_decode((string) base64_decode(strtr($m[1], '-_', '+/'), true), true);
        return is_array($json) && !array_is_list($json);
    }

    /**
     * The routing link as Happ gets it: the profile is always named
     * "MYrouting", so a new link replaces the same profile in Happ (Happ
     * overwrites a profile with the same name) instead of adding another.
     */
    public function happRoutingLink($link): string
    {
        if (!$this->validHappRouting($link)) {
            return '';
        }
        preg_match('~^happ://routing/((?:on)?add)/(.+)$~D', $link, $m);
        $json = json_decode(base64_decode(strtr($m[2], '-_', '+/')), true);
        $json['Name'] = 'MYrouting';
        return "happ://routing/{$m[1]}/" . base64_encode(json_encode($json, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    public function happRouting()
    {
        $this->prompt($this->i18n('prompt happ routing'), 'happ://routing/onadd/...', 'setHappRouting');
    }

    public function setHappRouting($text)
    {
        $text = trim((string) $text);
        $pac  = $this->getPacConf();
        if ($text === '-' || $text === '') {
            unset($pac['happrouting']);
        } elseif ($this->validHappRouting($text)) {
            $pac['happrouting'] = $text;
        } else {
            $this->send($this->input['chat'], 'wrong link: happ://routing/onadd/ or happ://routing/add/ followed by base64 JSON');
            return $this->routes();
        }
        $this->setPacConf($pac);
        $this->routes();
    }

    public function addClashRuleSet($c)
    {
        $p = $this->getPacConf();
        if (!empty($p['rulessetlist']) && $c['add-rule-providers']) {
            foreach ($p['rulessetlist'] as $k => $v) {
                if (!empty($v)) {
                    [$type, $behavior, $time, $url] = explode(':', $k, 4);
                    if (preg_match('~\.(mrs|yaml|yml)$~', $url, $m)) {
                        $c['rule-providers'][$url] = [
                            'type'     => 'http',
                            'url'      => $url,
                            'interval' => (int) $time,
                            'behavior' => $behavior,
                            'format'   => $m[1],
                        ];
                        switch ($type) {
                            case 'reject':
                            case 'REJECT':
                                array_unshift($c['rules'], [
                                    'RULE-SET', $url, strtoupper($type)
                                ]);
                                break;

                            default:
                                array_splice($c['rules'], count($c['rules']) - 1, 0, [[
                                    'RULE-SET', $url, strtoupper($type)
                                ]]);
                                break;
                        }
                    }
                }
            }
        }
        unset($c['add-rule-providers']);
        if (empty($c['rule-providers'])) {
            unset($c['rule-providers']);
        }
        return $c;
    }

    public function clashRules($c, $uid, $domain)
    {
        $tmp    = [];
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();
        foreach ($c['rules'] as $v) {
            if (array_key_exists('list', $v)) {
                if (($v['type'] ?? null) == 'RULE-SET') {
                    if (!empty($_GET['r']) && ($v['name'] ?? null) == $_GET['r']) {
                        header("Content-Disposition: attachment; filename={$v['name']}.yaml");
                        header('Content-Type: text/yaml');
                        switch ($v['name']) {
                            case 'process':
                            case 'package':
                                echo yaml_emit(['payload' => array_map(fn($e) => "PROCESS-NAME,$e", $v['list'])]);
                                break;

                            default:
                                echo yaml_emit(['payload' => array_map(function($e) {
                                    if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $e, $m)) {
                                        return "IP-CIDR,$e" . (empty($m[1]) ? '/32' : '');
                                    } else {
                                        return "DOMAIN-SUFFIX,$e";
                                    }
                                }, $v['list'])]);
                                break;

                        }
                        exit;
                    }
                    $c['rule-providers'][$v['name']] = [
                        'type'     => 'http',
                        'url'      => $this->subLink($scheme, $domain, 'cl', $uid, $v['name']),
                        'interval' => $v['interval'],
                        'behavior' => $v['behavior'],
                        'format'   => 'yaml',
                    ];
                    $tmp[] = "{$v['type']}, {$v['name']}, {$v['action']}";
                } else {
                    if (!empty($v['list'])) {
                        foreach ($v['list'] as $j) {
                            $tmp[] = "{$v['type']}, $j, {$v['action']}";
                        }
                    }
                }
            } else {
                $tmp[] = implode(', ', $v);
            }
        }
        $c['rules'] = $tmp;
        return $c;
    }

    public function replaceTags($subject, $tags)
    {
        // $subject is JSON: a tag written with quotes ("~pac~") is replaced by
        // a ready JSON value, any other tag sits inside a JSON string and its
        // value is escaped so it cannot break out of that string
        foreach ($tags as $k => $v) {
            if (($k[0] ?? null) !== '"') {
                $tags[$k] = substr(json_encode((string) $v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 1, -1);
            }
        }
        return str_replace(array_keys($tags), array_values($tags), $subject);
    }

    /**
     * sing-box 1.14: remote rule-sets download through http_client instead of
     * the deprecated download_detour (removed in 1.16). Converts every
     * download_detour (also ones coming from user templates) and declares the
     * referenced clients in top-level http_clients. A client without detour
     * dials directly, which is what download_detour "direct" meant.
     */
    public function singHttpClients(array $c): array
    {
        if (empty($c['route']['rule_set'])) {
            return $c;
        }
        $clients = [];
        foreach ($c['http_clients'] ?? [] as $v) {
            if (!empty($v['tag'])) {
                $clients[$v['tag']] = true;
            }
        }
        $add = function ($tag, $detour = null) use (&$c, &$clients) {
            if (empty($clients[$tag])) {
                $client = ['tag' => $tag];
                if ($detour !== null) {
                    $client['detour'] = $detour;
                }
                $c['http_clients'][] = $client;
                $clients[$tag]       = true;
            }
            return $tag;
        };
        foreach ($c['route']['rule_set'] as $k => $v) {
            if (($v['type'] ?? '') != 'remote') {
                continue;
            }
            if (array_key_exists('download_detour', $v)) {
                $detour = $v['download_detour'];
                unset($c['route']['rule_set'][$k]['download_detour']);
                if (empty($v['http_client'])) {
                    $c['route']['rule_set'][$k]['http_client'] = (empty($detour) || $detour == 'direct') ? 'direct' : "via-$detour";
                }
                if (!empty($detour) && $detour != 'direct') {
                    $add("via-$detour", $detour);
                }
            }
            if (($c['route']['rule_set'][$k]['http_client'] ?? '') == 'direct') {
                $add('direct');
            }
        }
        if (!empty($clients['direct']) && empty($c['route']['default_http_client'])) {
            $c['route']['default_http_client'] = 'direct';
        }
        return $c;
    }

    public function addRuleSet($route)
    {
        if (!empty($route['rules'])) {
            // the outbound => the rule the remote rule-sets join
            $t = [];
            foreach ($route['rules'] as $k => $v) {
                if (!empty($v['addruleset'])) {
                    $t[($v['outbound'] ?? '') ?: 'block'] = $k;
                }
            }
            $p = $this->getPacConf();
            if (!empty($p['rulessetlist'])) {
                foreach ($p['rulessetlist'] as $k => $v) {
                    if (!empty($v)) {
                        [$type, $time, $url] = explode(':', $k, 3);
                        if (preg_match('~\.srs$~', $url) && isset($t[$type]) && !empty($route['rules'][$t[$type]])) {
                            $route['rule_set'][] = [
                                "tag"             => $k,
                                "type"            => "remote",
                                "format"          => "binary",
                                "url"             => $url,
                                "http_client"     => "direct",
                                // sing-box wants a duration ("86400s"); the list keeps plain seconds for mihomo
                                "update_interval" => preg_match('~^\d+$~D', (string) $time) ? "{$time}s" : $time
                            ];
                            $route['rules'][$t[$type]]['rule_set'][] = $k;
                        }
                    }
                }
            }
            foreach ($route['rules'] as $k => $v) {
                unset($route['rules'][$k]['addruleset']);
            }
        }
        return $route;
    }

    public function cleanEmptyKeys(array $arr)
    {
        foreach ($arr as $k => $v) {
            if (empty($v)) {
                unset($arr[$k]);
            } elseif (is_array($v)) {
                $arr[$k] = $this->cleanEmptyKeys($v);
                if (empty($arr[$k])) {
                    unset($arr[$k]);
                }
            }
        }
        return $arr;
    }

    public function createSrs(string $name, array $rules)
    {
        $rules = $this->cleanEmptyKeys($rules);
        $name = preg_replace('~[^A-Za-z0-9_.-]~', '', $name) ?: 'ruleset';
        header("Content-Disposition: attachment; filename=$name.srs");
        header('Content-Type: application/binary');
        foreach ($rules as $k => $v) {
            if (array_key_exists('domain_suffix', $v)) {
                foreach ($v['domain_suffix'] as $j) {
                    if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $j, $m)) {
                        $domains[] = $j;
                    } else {
                        $ips[] = $j . (empty($m[1]) ? '/32' : '');
                    }
                }
                unset($rules[$k]['domain_suffix']);
                if (!empty($domains)) {
                    $rules[$k]['domain_suffix'] = $domains;
                }
                if (!empty($ips)) {
                    $rules[$k]['ip_cidr'] = $ips;
                }
            }
        }
        $json = json_encode([
            'version' => 1,
            'rules'   => $rules ?: [],
        ]);
        // compiled once per content: clients refresh rule-sets often and
        // compiling on every request would let them load the server
        $dir = '/tmp/srs';
        @mkdir($dir, 0700);
        $f = "$dir/" . hash('sha256', $json);
        if (!is_file("$f.srs")) {
            $tmp = "$f." . bin2hex(random_bytes(6));
            file_put_contents($tmp, $json);
            exec('sing-box rule-set compile --output ' . escapeshellarg("$tmp.srs") . ' ' . escapeshellarg($tmp));
            @unlink($tmp);
            if (is_file("$tmp.srs")) {
                rename("$tmp.srs", "$f.srs");
            }
            // keep the cache small: drop compiled sets not used for a day
            foreach (glob("$dir/*.srs") ?: [] as $old) {
                if (filemtime($old) < time() - 86400) {
                    @unlink($old);
                }
            }
        } else {
            @touch("$f.srs");
        }
        if (!is_file("$f.srs")) {
            // compile failed: an error, not an empty file the client cannot parse
            error_log("rule-set $name: sing-box compile failed");
            http_response_code(500);
            exit;
        }
        readfile("$f.srs");
        exit;
    }

    public function createRuleSet($route, $uid, $domain)
    {
        $ruleset = [];
        $scheme  = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        foreach ($route['rules'] as $k => $v) {
            if (!empty($v['createruleset'])) {
                foreach ($v['createruleset'] as $r) {
                    if (!empty($_GET['r']) && ($r['name'] ?? null) == $_GET['r']) {
                        $this->createSrs($r['name'], $r['rules']);
                    }
                    $ruleset[] = [
                        "tag"             => $r['name'],
                        "url"             => $this->subLink($scheme, $domain, 'si', $uid, $r['name']),
                        "update_interval" => $r['interval'],
                        "type"            => "remote",
                        "format"          => "binary",
                        "http_client"     => "direct",
                    ];
                    $route['rules'][$k]['rule_set'][] = $r['name'];
                }
                unset($route['rules'][$k]['createruleset']);
                if (empty($route['rules'][$k]['rule_set'])) {
                    unset($route['rules'][$k]);
                }
            }
        }
        if (!empty($route['rules'])) {
            $route['rules']    = array_values($route['rules']);
        }
        $route['rule_set'] = array_merge(($route['rule_set'] ?? null) ?: [], $ruleset ?: []);
        if (empty($route['rule_set'])) {
            unset($route['rule_set']);
        }
        return $route;
    }

    /**
     * Domain for links in a subscription: ?cdn= or the request Host,
     * only when it is a valid host name, else the configured one.
     */
    public function requestDomain($pac)
    {
        foreach ([$_GET['cdn'] ?? null, $_SERVER['SERVER_NAME'] ?? null] as $d) {
            if (is_string($d) && $d !== '' && $this->validHost($d)) {
                return $d;
            }
        }
        return $this->getDomain(($pac['transport'] ?? null) != 'Reality');
    }
}
