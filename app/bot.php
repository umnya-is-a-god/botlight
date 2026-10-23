<?php

class Bot
{
    public $input;
    public $adguard;
    public $update;
    public $ip;
    public $limit;
    public $key;
    public $file;
    public $dns;
    public $mtu;
    public $logs;
    public $reg;
    public $pool;
    public $api;
    public $pac;
    public $i18n;
    public $language;
    public $selfupdate;
    public $last;
    public $dontshowcron;
    public $input_raw;
    public $time;
    public $time2;
    public $time3;
    public $time_xray_stats;
    public $time_warp_status;
    public $admin;
    public $ports;

    public function __construct($key, $i18n)
    {
        $api = getenv('TELEGRAM_API') ?: 'api.telegram.org';
        $this->key      = $key;
        $this->api      = "https://$api/bot$key/";
        $this->file     = "https://$api/file/bot$key/";
        $this->pac      = '/config/pac.json';
        $this->ip       = filter_var(getenv('IP'), FILTER_VALIDATE_IP) ?: '';
        $this->i18n     = $i18n;
        $this->language = $this->getPacConf()['language'] ?: 'en';
        $this->dns      = '1.1.1.1, 8.8.8.8';
        $this->mtu      = 1350;
        $this->limit    = $this->getPacConf()['limitpage'] ?: 5;
        $this->adguard  = '/config/AdGuardHome.yaml';
        $this->update   = '/update/json';
        $this->logs = [
            'nginx_default_access',
            'nginx_domain_access',
            'upstream_access',
            'xray',
        ];
        $this->reg = '~' . implode('|', [
            'GET / HTTP',
            'GET /favicon.ico HTTP',
            preg_quote($this->getHashBot(1))
        ]) . '~';
        $this->ports = [
            'ad'    => '853',
            'dnstt' => '53/udp',
        ];
    }

    public function input($data = false)
    {
        $this->admin     = false;
        $this->input_raw = $input = $data ?: json_decode(file_get_contents('php://input'), true);
        $this->input     = [
            'message'           => $input['callback_query']['message']['text'] ?? $input['message']['text'] ?? $input['channel_post']['text'] ?? '',
            'message_id'        => $input['callback_query']['message']['message_id'] ?? $input['message']['message_id'] ?? $input['channel_post']['message_id'],
            'chat'              => $input['message']['chat']['id'] ?? $input['callback_query']['message']['chat']['id'] ?? $input['channel_post']['chat']['id'] ?? $input['my_chat_member']['chat']['id'],
            'from'              => $input['message']['from']['id'] ?? $input['inline_query']['from']['id'] ?? $input['callback_query']['from']['id'] ?? $input['channel_post']['chat']['id'] ?? $input['my_chat_member']['from']['id'],
            'username'          => $input['message']['from']['username'] ?? $input['inline_query']['from']['username'] ?? $input['callback_query']['from']['username'],
            'query'             => $input['inline_query']['query'] ?? '',
            'inlid'             => $input['inline_query']['id'] ?? '',
            'group'             => !empty($input['message']['chat']['type']) && 'group' == $input['message']['chat']['type'],
            'sticker_id'        => $input['message']['sticker']['file_id'] ?? false,
            'channel'           => !empty($input['channel_post']['message_id']),
            'callback'          => $input['callback_query']['data'] ?? false,
            'callback_id'       => $input['callback_query']['id'] ?? false,
            'photo'             => $input['message']['photo'] ?? false,
            'file_name'         => $input['message']['document']['file_name'] ?? false,
            'file_id'           => $input['message']['document']['file_id'] ?? false,
            'caption'           => $input['message']['caption'] ?? false,
            'reply'             => $input['message']['reply_to_message']['message_id'] ?? false,
            'reply_from'        => $input['message']['reply_to_message']['from']['id'] ??  $input['callback_query']['message']['reply_to_message']['from']['id'] ?? false,
            'reply_text'        => $input['message']['reply_to_message']['text'] ?? false,
            'new_member_id'     => $input['my_chat_member']['new_chat_member']['user']['id'] ?? false,
            'new_member_status' => $input['my_chat_member']['new_chat_member']['status'] ?? false,
        ];
        $this->auth();
        if ($this->admin) {
            $this->session();
            $this->action();
        }
        $this->callbackCheck();
    }

    public function auth()
    {
        $file = __DIR__ . '/config.php';
        require $file;
        $from = is_int($this->input['from']) ? $this->input['from'] : 0;
        if (empty($c['admin'])) {
            // the first admin is whoever writes to the bot first, and only
            // from a private chat with a real user id (not a channel, group
            // or an update without a sender)
            if ($from <= 0 || empty($this->input_raw['message']) || ($this->input_raw['message']['chat']['type'] ?? '') !== 'private') {
                return;
            }
            $c['admin'] = [$from];
            // the name from the Telegram profile, shown in Settings
            $first = trim((string) ($this->input_raw['message']['from']['first_name'] ?? ''));
            if ($this->validName($first)) {
                $c['admin_names'][$from] = $first;
            }
            file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        } elseif (!is_array($c['admin'])) {
            $c['admin'] = [$c['admin']];
            file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        }
        if ($from !== 0 && in_array($from, array_map('intval', $c['admin']), true)) {
            $this->admin = true;
        }
    }

    public function callbackCheck()
    {
        if (empty($this->callback) && !empty($this->input['callback_id'])) {
            $this->answer($this->input['callback_id'], !empty($GLOBALS['debug']) ? $this->input['callback'] : false);
        }
    }

    public function session()
    {
        session_id($this->input['from']);
        @session_start();
        if (!empty($_SESSION['reply'])) {
            if (empty($this->input['reply'])) {
                foreach ($_SESSION['reply'] as $k => $v) {
                    $this->delete($this->input['chat'], $k);
                }
                unset($_SESSION['reply']);
            }
        }
    }

    public function action()
    {
        switch (true) {
            // смена айпи сервера
            case preg_match('~^/menu$~', $this->input['message'], $m):
            case preg_match('~^/start$~', $this->input['message'], $m):
            case preg_match('~^/menu$~', $this->input['callback'], $m):
            case preg_match('~^/menu (?P<type>pac|adguard|config|lang|oc|mirror|update)$~', $this->input['callback'], $m):
                $this->menu(type: $m['type'] ?? false, arg: $m['arg'] ?? false);
                break;
            case preg_match('~^/changeTransport(?: (\w+))?$~', $this->input['callback'], $m):
                $this->changeTransport($m[1] ?? false);
                break;
            case preg_match('~^/mirror$~', $this->input['message'], $m):
                $this->menu('mirror');
                break;
            case preg_match('~^/happRouting$~', $this->input['callback'], $m):
                $this->happRouting();
                break;
            case preg_match('~^/mainOutbound$~', $this->input['callback'], $m):
                $this->mainOutbound();
                break;
            case preg_match('~^/importIps (.+)$~', $this->input['callback'], $m):
                $this->importIps($m[1]);
                break;
            case preg_match('~^/switchBanIp$~', $this->input['callback'], $m):
                $this->switchBanIp();
                break;
            case preg_match('~^/switchMonthlyStats$~', $this->input['callback'], $m):
                $this->switchMonthlyStats();
                break;
            case preg_match('~^/setIpLimit$~', $this->input['callback'], $m):
                $this->setIpLimit();
                break;
            case preg_match('~^/setBridge$~', $this->input['callback'], $m):
                $this->bridgePrompt();
                break;
            case preg_match('~^/searchLogs (.+)$~', $this->input['message'], $m):
                $this->searchLogs($m[1]);
                break;
            case preg_match('~^/searchLogs (.+?)(?:\s(.+?))?(?:\s(.+?))?(?:\s(.+?))?$~', $this->input['callback'], $m):
                $this->searchLogs($m[1], $m[2], $m[3], $m[4]);
                break;
            case preg_match('~^/switchSilence$~', $this->input['callback'], $m):
                $this->switchSilence();
                break;
            case preg_match('~^/autoScanTimeout$~', $this->input['callback'], $m):
                $this->autoScanTimeout();
                break;
            case preg_match('~^/autoupdate$~', $this->input['callback'], $m):
                $this->autoupdate();
                break;
            case preg_match('~^/ports$~', $this->input['callback'], $m):
                $this->ports();
                break;
            case preg_match('~^/analysisIp(?:\s(\d+))?$~', $this->input['callback'], $m):
                $this->analysisIp($m[1] ?: 0);
                break;
            case preg_match('~^/ipMenu$~', $this->input['callback'], $m):
                $this->ipMenu();
                break;
            case preg_match('~^/cleanDeny(?:\s(\d))?$~', $this->input['callback'], $m):
                $this->cleanDeny($m[1]);
                break;
            case preg_match('~^/denyList (.+?)(?:\s(\d))?$~', $this->input['callback'], $m):
                $this->denyList($m[1], $m[2] ?: 0);
                break;
            case preg_match('~^/cleanLogs (.+?)(?:\s(1))?$~', $this->input['callback'], $m):
                $this->cleanLogs($m[1], $m[2]);
                break;
            case preg_match('~^/allowIp (.+?) (\d+)(?:\s(\d+))?$~', $this->input['callback'], $m):
                $this->allowIp($m[1], $m[2], $m[3]);
                break;
            case preg_match('~^/searchIp (.+)$~', $this->input['callback'], $m):
                $this->searchIp($m[1]);
                break;
            case preg_match('~^/searchSuspiciousIp (.+)$~', $this->input['callback'], $m):
                $this->searchSuspiciousIp($m[1]);
                break;
            case preg_match('~^/denyIp (.+?)(?:\s(.+?)\s(\d+?)\s(\d))?$~', $this->input['callback'], $m):
                $this->denyIp($m[1], $m[2], $m[3], $m[4]);
                break;
            case preg_match('~^/whiteIp (.+?)(?:\s(.+?)\s(\d+?)\s(\d))?$~', $this->input['callback'], $m):
                $this->whiteIp($m[1], $m[2], $m[3], $m[4]);
                break;
            case preg_match('~^/adgFillAllowedClients(?: (\d+))?$~', $this->input['callback'], $m):
                $this->adgFillAllowedClients($m[1] ?: false);
                break;
            case preg_match('~^/addLinkDomain$~', $this->input['callback'], $m):
                $this->addLinkDomain();
                break;
            case preg_match('~^/id$~', $this->input['message'], $m):
                $this->send($this->input['chat'], "your id: {$this->input['from']}\nchat id: {$this->input['chat']}", $this->input['message_id']);
                break;
            case preg_match('~^/adguardChBr$~', $this->input['callback'], $m):
                $this->adguardChBr();
                break;
            case preg_match('~^/deleteAll (includelist|blocklist|warplist|rulessetlist|white|deny)$~', $this->input['callback'], $m):
                $this->deleteAll($m[1]);
                break;
            case preg_match('~^/exportList (includelist|blocklist|warplist|rulessetlist|white|deny)$~', $this->input['callback'], $m):
                $this->exportList($m[1]);
                break;
            case preg_match('~^/hidePort (\w+)$~', $this->input['callback'], $m):
                $this->hidePort($m[1]);
                break;
            case preg_match('~^/deleteYes (includelist|blocklist|warplist|rulessetlist|white|deny)$~', $this->input['callback'], $m):
                $this->deleteYes($m[1]);
                break;
            case preg_match('~^/pacMenu (\d+)$~', $this->input['callback'], $m):
                $this->pacMenu($m[1]);
                break;
            case preg_match('~^/changelog$~', $this->input['callback'], $m):
                $this->changelog();
                break;
            case preg_match('~^/applyupdatebot$~', $this->input['callback'], $m):
                $this->applyupdatebot();
                break;
            case preg_match('~^/restart$~', $this->input['callback'], $m):
                $this->restart();
                break;
            case preg_match('~^/rebuild$~', $this->input['callback'], $m):
                $this->rebuildMenu();
                break;
            case preg_match('~^/rebuildYes$~', $this->input['callback'], $m):
                $this->rebuild();
                break;
            case preg_match('~^/branches$~', $this->input['callback'], $m):
                $this->branches();
                break;
            case preg_match('~^/changeBranch (\d+)$~', $this->input['callback'], $m):
                $this->changeBranch($m[1]);
                break;
            case preg_match('~^/getMirror$~', $this->input['callback'], $m):
                $this->getMirror();
                break;
            case preg_match('~^/logs$~', $this->input['callback'], $m):
                $this->logs();
                break;
            case preg_match('~^/dnstt$~', $this->input['callback'] ?: $this->input['message'], $m):
                $this->dnstt(!empty($this->input['callback']));
                break;
            case preg_match('~^/dnsttDownload$~', $this->input['callback'], $m):
                $this->dnsttDownload();
                break;
            case preg_match('~^/dnsttDomain$~', $this->input['callback'], $m):
                $this->dnsttDomain();
                break;
            case preg_match('~^/dnsttPassword$~', $this->input['callback'], $m):
                $this->dnsttPassword();
                break;
            case preg_match('~^/getLog (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->getLog(...explode('_', $m['arg']));
                break;
            case preg_match('~^/clearLog (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->clearLog(...explode('_', $m['arg']));
                break;
            case preg_match('~^/cleanLog$~', $this->input['callback'], $m):
                $this->cleanLog();
                break;
            case preg_match('~^/debug$~', $this->input['message'], $m):
                $this->debug();
                break;
            case preg_match('~^/backup$~', $this->input['callback'], $m):
                $this->backup();
                break;
            case preg_match('~^/selfssl$~', $this->input['callback'], $m):
                $this->selfssl();
                break;
            case preg_match('~^/changeCamouflage$~', $this->input['callback'], $m):
                $this->changeCamouflage();
                break;
            case preg_match('~^/changeOcDomain$~', $this->input['callback'], $m):
                $this->changeOcDomain();
                break;
            case preg_match('~^/changeOcPass$~', $this->input['callback'], $m):
                $this->changeOcPass();
                break;
            case preg_match('~^/addOcUser$~', $this->input['callback'], $m):
                $this->addOcUser();
                break;
            case preg_match('~^/addXrUser$~', $this->input['callback'], $m):
                $this->addXrUser();
                break;
            case preg_match('~^/renameXrUser (\d+)$~', $this->input['callback'], $m):
                $this->renameXrUser($m[1]);
                break;
            case preg_match('~^/resetXrUser (\d+)$~', $this->input['callback'], $m):
                $this->resetXrUser($m[1]);
                break;
            case preg_match('~^/resetXrStats$~', $this->input['callback'], $m):
                $this->resetXrStats();
                break;
            case preg_match('~^/checkdns$~', $this->input['callback'], $m):
                $this->checkdns();
                break;
            case preg_match('~^/adguardpsswd$~', $this->input['callback'], $m):
                $this->adguardpsswd();
                break;
            case preg_match('~^/setAdguardKey$~', $this->input['callback'], $m):
                $this->setAdguardKey();
                break;
            case preg_match('~^/addadmin$~', $this->input['callback'], $m):
                $this->enterAdmin();
                break;
            case preg_match('~^/enterPage$~', $this->input['callback'], $m):
                $this->enterPage();
                break;
            case preg_match('~^/adguardreset$~', $this->input['callback'], $m):
                $this->adguardreset();
                break;
            case preg_match('~^/addupstream$~', $this->input['callback'], $m):
                $this->addupstream();
                break;
            case preg_match('~^/setSSL (\w+)$~', $this->input['callback'], $m):
                $this->setSSL($m[1]);
                break;
            case preg_match('~^/lang (\w+)$~', $this->input['callback'], $m):
                $this->setLang($m[1]);
                break;
            case preg_match('~^/deletessl$~', $this->input['callback'], $m):
                $this->deleteSSL();
                break;
            case preg_match('~^/deloc (\d+)$~', $this->input['callback'], $m):
                $this->deloc($m[1]);
                break;
            case preg_match('~^/ocUser (\d+)$~', $this->input['callback'], $m):
                $this->ocUser((int) $m[1]);
                break;
            case preg_match('~^/renameOcUser (\d+)$~', $this->input['callback'], $m):
                $this->renameOcUser((int) $m[1]);
                break;
            case preg_match('~^/userXr (\d+)$~', $this->input['callback'], $m):
                $this->userXr($m[1]);
                break;
            case preg_match('~^/choiceTemplate (.+)$~', $this->input['callback'], $m):
                $this->choiceTemplate($m[1]);
                break;
            case preg_match('~^/templateUser (sing|clash) (\d+)$~', $this->input['callback'], $m):
                $this->templateUser($m[1], $m[2]);
                break;
            case preg_match('~^/switchXr (\d+)$~', $this->input['callback'], $m):
                $this->switchXr($m[1]);
                break;
            case preg_match('~^/delxr (\d+)$~', $this->input['callback'], $m):
                $this->delxr($m[1]);
                break;
            case preg_match('~^/listXr (\d+)$~', $this->input['callback'], $m):
                $this->listXr($m[1]);
                break;
            case preg_match('~^/deladmin (\d+)$~', $this->input['callback'], $m):
                $this->delAdmin($m[1]);
                break;
            case preg_match('~^/adminCard (\d+)$~', $this->input['callback'], $m):
                $this->adminCard($m[1]);
                break;
            case preg_match('~^/renameAdmin (\d+)$~', $this->input['callback'], $m):
                $this->renameAdmin($m[1]);
                break;
            case preg_match('~^/qrXray (\d+)(?:_(\d+))?$~', $this->input['callback'], $m):
                $this->qrXray($m[1], $m[2] ?: false);
                break;
            case preg_match('~^/delupstream (\d+)$~', $this->input['callback'], $m):
                $this->delupstream($m[1]);
                break;
            case preg_match('~^/deldomain$~', $this->input['callback'], $m):
                $this->delDomain();
                break;
            case preg_match('~^/addNipdomain$~', $this->input['callback'], $m):
                $this->addNipdomain();
                break;
            case preg_match('~^/(?P<action>change|delete)(?P<typelist>includelist|blocklist|warplist|rulessetlist|white|deny) (?P<arg>\d+)(?: (?P<page>\d+))?$~', $this->input['callback'], $m):
                $this->listPacChange($m['typelist'], $m['action'], $m['arg'], $m['page'] ?: 0);
                break;
            case preg_match('~^/domain$~', $this->input['callback'], $m):
                $this->domain();
                break;
            case preg_match('~^/warp$~', $this->input['callback'], $m):
                $this->warp();
                break;
            case preg_match('~^/warpPlus$~', $this->input['callback'], $m):
                $this->warpPlus();
                break;
            case preg_match('~^/xray(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xray($m[1] ?: 0);
                break;
            case preg_match('~^/xtlsblock(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsblock($m[1] ?: 0);
                break;
            case preg_match('~^/routes(?: (\d+))?$~', $this->input['callback'], $m):
                $this->routes($m[1] ?: 0);
                break;
            case preg_match('~^/xtlswarp(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlswarp($m[1] ?: 0);
                break;
            case preg_match('~^/xtlsrulesset(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsrulesset($m[1] ?: 0);
                break;
            case preg_match('~^/templateCopy (sing|clash)(?: (.+))?$~', $this->input['callback'], $m):
                $this->templateCopy($m[1], $m[2]);
                break;
            case preg_match('~^/delTemplate (sing|clash)(?: (.+))?$~', $this->input['callback'], $m):
                $this->delTemplate($m[1], $m[2]);
                break;
            case preg_match('~^/downloadOrigin (sing|clash)$~', $this->input['callback'], $m):
                $this->downloadOrigin($m[1]);
                break;
            case preg_match('~^/downloadTemplate (sing|clash)(?: (.+))?$~', $this->input['callback'], $m):
                $this->downloadTemplate($m[1], $m[2]);
                break;
            case preg_match('~^/defaultTemplate (sing|clash)(?: (.+))?$~', $this->input['callback'], $m):
                $this->defaultTemplate($m[1], $m[2]);
                break;
            case preg_match('~^/templates (sing|clash)$~', $this->input['callback'], $m):
                $this->templates($m[1]);
                break;
            case preg_match('~^/templateAdd (sing|clash)$~', $this->input['callback'], $m):
                $this->templateAdd($m[1]);
                break;
            case preg_match('~^/changeFakeDomain$~', $this->input['callback'], $m):
                $this->changeFakeDomain();
                break;
            case preg_match('~^/autoCleanLogs$~', $this->input['callback'], $m):
                $this->autoCleanLogs();
                break;
            case preg_match('~^/selfFakeDomain$~', $this->input['callback'], $m):
                $this->selfFakeDomain();
                break;
            case preg_match('~^/include (includelist|blocklist|warplist|rulessetlist|white|deny)$~', $this->input['callback'], $m):
                $this->include($m[1]);
                break;
            case preg_match('~^/addOverrideHtml$~', $this->input['callback'], $m):
                $this->addOverrideHtml();
                break;
            case preg_match('~^/delOverrideHtml$~', $this->input['callback'], $m):
                $this->delOverrideHtml();
                break;
            case preg_match('~^/backupPassword$~', $this->input['callback'], $m):
                $this->backupPassword();
                break;
            case preg_match('~^/export$~', $this->input['callback'], $m):
                $this->sendBackup();
                break;
            case preg_match('~^/import$~', $this->input['callback'], $m):
                $this->import();
                break;
            case preg_match('~^/importList (includelist|blocklist|warplist|rulessetlist|white|deny)$~', $this->input['callback'], $m):
                $this->importList($m[1]);
                break;
            case !empty($this->input['reply']):
                $this->reply();
                break;
        }
    }

    public function restartXray($c, $norestart = false, $rename = null)
    {
        $c['inbounds'][0]['settings']['clients'] = array_values($c['inbounds'][0]['settings']['clients']);
        // Xray's access log lists every site each user opens: kept only while
        // the IP limit needs it (it is read to count IPs per user). Error log
        // at warning: "info" also prints every destination.
        $c['log']['access']   = empty($this->getPacConf()['ip_limit']) ? 'none' : '/logs/xray';
        $c['log']['loglevel'] = 'warning';
        foreach ($c['inbounds'] as $v) {
            if ($v['tag'] == 'api') {
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
            if ($v['outboundTag'] == 'api') {
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
        $c['api'] = [
            'services' => ['StatsService'],
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
        if (empty($norestart)) {
            // Xray's counters start from zero after the restart. In one locked
            // step (the cron loop updates the same stats): latest counters
            // under the running config's names, into the totals, the renamed
            // user's record to the new name, new config, restart.
            $this->updateXrayStats(function ($p) use ($c, $rename) {
                $running = array_map(fn($e) => (string) ($e['email'] ?? ''), $this->getXray()['inbounds'][0]['settings']['clients'] ?? []);
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
                file_put_contents('/config/xray.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                $this->ssh('pkill xray', 'xr');
                // not without the egress filter (see scripts/start_xray.sh)
                $this->ssh('[ -e /tmp/fw_failed ] || xray run -config /xray.json > /dev/null 2>&1 &', 'xr');
                return $p;
            });
        } else {
            file_put_contents('/config/xray.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        }
    }

    public function setLang($lang)
    {
        $conf = $this->getPacConf();
        $this->language = $conf['language'] = $lang;
        $this->setPacConf($conf);
        $this->menu('config');
    }



    public function changeCamouflage()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter camouflage key'),
            $this->input['message_id'],
            reply: $this->i18n('enter camouflage key'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chockey',
            'args'           => [],
        ];
    }

    public function changeOcDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter subdomain'),
            $this->input['message_id'],
            reply: $this->i18n('enter subdomain'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chOcSubdomain',
            'args'           => [],
        ];
    }


    public function changeOcPass()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter pass'),
            $this->input['message_id'],
            reply: $this->i18n('enter password'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chocpass',
            'args'           => [],
        ];
    }

    public function addOcUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter name'),
            $this->input['message_id'],
            reply: $this->i18n('enter name'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addocus',
            'args'           => [],
        ];
    }

    public function addXrUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter name'),
            $this->input['message_id'],
            reply: $this->i18n('enter name:uuid [,name:uuid]'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addxrus',
            'args'           => [],
        ];
    }

    public function renameXrUser($i)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter name'),
            $this->input['message_id'],
            reply: $this->i18n('enter name'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'renXrUs',
            'args'           => [$i],
        ];
    }

    public function addOverrideHtml()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('attach html'),
            $this->input['message_id'],
            reply: $this->i18n('attach html'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setOverrideHtml',
            'args'           => [],
        ];
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
            file_put_contents('/app/webapp/override.html', $f);
        }
        $this->menu('config');
    }

    public function delOverrideHtml()
    {
        @unlink('/app/webapp/override.html');
        $this->menu('config');
    }

    public function restartOcserv($conf)
    {
        file_put_contents('/config/ocserv.conf', $conf);
        $this->ssh('pkill ocserv', 'oc');
        $pac = $this->getPacConf();
        if (!empty($pac['ocserv']) && !empty($this->getHashSubdomain('oc'))) {
            $this->ssh('ocserv -c /etc/ocserv/ocserv.conf', 'oc');
        }
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
        $this->menu('oc');
    }

    public function chockey($pass)
    {
        // a quoted value in ocserv.conf and a query string in the client link
        if (!preg_match('#^[A-Za-z0-9._~-]{1,64}$#D', $pass = trim((string) $pass))) {
            $this->send($this->input['chat'], 'wrong secret: 1-64 characters A-Z a-z 0-9 . _ ~ -');
            return $this->menu('oc');
        }
        $c = file_get_contents('/config/ocserv.conf');
        $t = preg_replace('~^camouflage_secret[^\n]+~sm', "camouflage_secret = \"$pass\"", $c);
        $this->restartOcserv($t);
        $this->menu('oc');
    }

    public function chocdomain($domain)
    {
        if ($domain && !$this->validHost($domain)) {
            return;
        }
        $oc = $this->getHashSubdomain('oc');
        $c  = file_get_contents('/config/ocserv.conf');
        $t  = preg_replace('~^default-domain[^\n]+~sm', "default-domain = $oc.$domain", $c);
        $this->restartOcserv($t);
    }

    public function chocpass($pass)
    {
        if (!$this->validSecret($pass = trim((string) $pass))) {
            $this->send($this->input['chat'], 'wrong password: 1-128 printable characters, no ":"');
            return;
        }
        $pac = $this->getPacConf();
        $pac['ocserv'] = $pass;
        $this->setPacConf($pac);
        $clients = $this->getClientsOc();
        foreach ($clients as $k => $v) {
            $this->ssh('echo ' . escapeshellarg($pass) . ' | ocpasswd -c /etc/ocserv/ocserv.passwd ' . escapeshellarg($v), 'oc');
        }
        $this->restartOcserv(file_get_contents('/config/ocserv.conf'));
        $this->menu('oc');
    }

    public function importList($type)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('send the export file:'),
            $this->input['message_id'],
            reply: $this->i18n('send the export file:'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'importListFile',
            'args'           => [$type],
        ];
    }

    public function importListFile($message, $type)
    {
        if (empty($this->input['file_id'])) {
            $this->send($this->input['chat'], 'send the list as a file');
            return;
        }
        $r = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        $f = file_get_contents($this->file . $r['result']['file_path']);
        if (!empty($f)) {
            foreach (explode("\n", $f) as $v) {
                if (!empty($s = trim($v))) {
                    $t = explode(';', $s);
                    if ($type == 'rulessetlist') {
                        if (preg_match('~^.+:.+:https?://.+~', $t[0])) {
                            $list[$t[0]] = (bool) $t[1];
                        }
                    } else {
                        $list[$t[0]] = (bool) $t[1];
                    }
                }
            }
            $p = $this->getPacConf();
            $p[$type] = $list;
            $this->setPacConf($p);
        }
        $this->backXtlsList($type);
    }

    public function cron()
    {
        $period = 10;
        while (true) {
            $this->checkVersion();
            $this->checkBackup();
            $this->checkLogs();
            $this->checkResetXrayStats();
            $this->checkCert();
            $this->autoAnalyzeLogs();
            $this->xrayStatsUser();
            $this->checkWarpStatus();
            sleep($period);
        }
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
        $l = fopen('/config/xray.stats.lock', 'c');
        flock($l, LOCK_EX);
        try {
            $this->setXrayStats($fn($this->getXrayStats()));
        } finally {
            flock($l, LOCK_UN);
            fclose($l);
        }
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

    public function autoAnalyzeLogs()
    {
        try {
            $pac = $this->getPacConf();
            if (!empty($pac['autoscan'])) {
                require __DIR__ . '/config.php';
                if (!empty($c['admin']) && (empty($this->time3) || ((time() - $this->time3) > $pac['autoscan_timeout']))) {
                    $this->time3 = time();
                    $r = $this->analysisIp(return: 1);
                    if (!empty($r)) {
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
                        if ($pac['silence'] == 0 || $pac['silence'] == 1) {
                            foreach ($c['admin'] as $k => $v) {
                                $this->send($v, "suspicious ips found: $text" . ($ban ? "\nbanned:$ban" : ''), button: $ips ?: [[
                                    [
                                        'text'          => $this->i18n('analyze'),
                                        'callback_data' => '/analysisIp',
                                    ],
                                ]], disable_notification: $pac['silence'] ? true : false);
                            }
                        }
                    }
                }
            }
        } catch (Exception $e) {
            file_put_contents('/logs/php_error', $e->getMessage());
        }
    }

    public function checkBackup()
    {
        $c = $this->getPacConf();
        if (!empty($c['backup'])) {
            $now = time();
            [$start, $period] = explode('/', $c['backup']);
            $start  = strtotime(trim($start));
            $period = strtotime(trim($period), 0);

            if (
                !empty($start)
                && !empty($period)
                && $now >= $start
            ) {
                // Вычисляем, сколько полных периодов прошло с момента start
                $elapsed = $now - $start;
                $periodsElapsed = floor($elapsed / $period);

                // Время последнего планового бэкапа
                $lastScheduledBackup = $start + ($periodsElapsed * $period);

                // Проверяем, делали ли уже бэкап в этом периоде
                $lastBackupTime = $c['last_backup_time'] ?? 0;

                // Если последний бэкап был сделан до начала текущего периода - делаем бэкап
                if ($lastBackupTime < $lastScheduledBackup) {
                    $c['last_backup_time'] = $now;
                    $this->setPacConf($c);
                    $this->sendBackup();
                }
            }
        }
    }

    public function checkResetXrayStats()
    {
        $pac = $this->getPacConf();
        if (!empty($pac['reset_monthly'])) {
            $now    = time();
            $start  = strtotime('first day of previous month midnight');
            $period = strtotime('1 month', 0);

            if (
                !empty($start)
                && !empty($period)
                && $now >= $start
            ) {
                // Вычисляем, сколько полных периодов прошло с момента start
                $elapsed = $now - $start;
                $periodsElapsed = floor($elapsed / $period);

                // Время последнего планового сброса статистики
                $lastScheduledReset = $start + ($periodsElapsed * $period);

                // Проверяем, делали ли уже сброс в этом периоде
                $lastResetTime = $pac['last_reset_xray_time'] ?? 0;

                // Если последний сброс был сделан до начала текущего периода - делаем сброс
                if ($lastResetTime < $lastScheduledReset) {
                    $pac['last_reset_xray_time'] = $now;
                    $this->setPacConf($pac);
                    $this->resetXrStats(1);
                    require __DIR__ . '/config.php';
                    foreach ($c['admin'] as $admin) {
                        $this->send($admin, "vless: reset stats");
                    }
                }
            }
        }
    }

    public function checkLogs()
    {
        $c = $this->getPacConf();
        if (!empty($c['autocleanlogs'])) {
            $now = time();
            [$start, $period] = explode('/', $c['autocleanlogs']);
            $start  = strtotime(trim($start));
            $period = strtotime(trim($period), 0);

            if (
                !empty($start)
                && !empty($period)
                && $now >= $start
            ) {
                // Вычисляем, сколько полных периодов прошло с момента start
                $elapsed = $now - $start;
                $periodsElapsed = floor($elapsed / $period);

                // Время последней плановой очистки логов
                $lastScheduledClean = $start + ($periodsElapsed * $period);

                // Проверяем, делали ли уже очистку в этом периоде
                $lastCleanTime = $c['last_clean_logs_time'] ?? 0;

                // Если последняя очистка была сделана до начала текущего периода - делаем очистку
                if ($lastCleanTime < $lastScheduledClean) {
                    $c['last_clean_logs_time'] = $now;
                    $this->setPacConf($c);
                    $this->cleanLog();
                }
            }
        }
    }

    public function cleanQueue(): void
    {
        $r = $this->request('deleteWebhook', []);
        $r = $this->request('getUpdates', ['offset' => -1]);
    }


    /**
     * Backups hold every key and password of the server and go to Telegram,
     * so they are encrypted: AES-256-GCM (authenticated) with a key from the
     * backup password via PBKDF2-SHA256.
     */
    public function encryptBackup(string $plain, string $pass): string
    {
        $salt = random_bytes(16);
        $iv   = random_bytes(12);
        $iter = 600000;
        $key  = hash_pbkdf2('sha256', $pass, $salt, $iter, 32, true);
        $data = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return json_encode([
            'vpnbot_backup' => 1,
            'kdf'           => 'pbkdf2-sha256',
            'iter'          => $iter,
            'salt'          => base64_encode($salt),
            'cipher'        => 'aes-256-gcm',
            'iv'            => base64_encode($iv),
            'tag'           => base64_encode($tag),
            'data'          => base64_encode($data),
        ]);
    }

    // null: wrong password or damaged file
    public function decryptBackup(array $env, string $pass): ?string
    {
        if (($env['cipher'] ?? '') !== 'aes-256-gcm' || ($env['kdf'] ?? '') !== 'pbkdf2-sha256') {
            return null;
        }
        $iter  = max(100000, min(10000000, (int) ($env['iter'] ?? 0)));
        $key   = hash_pbkdf2('sha256', $pass, (string) base64_decode($env['salt'] ?? ''), $iter, 32, true);
        $plain = openssl_decrypt((string) base64_decode($env['data'] ?? ''), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, (string) base64_decode($env['iv'] ?? ''), (string) base64_decode($env['tag'] ?? ''));
        return $plain === false ? null : $plain;
    }

    // $file: also keep a plain copy there (local, for the bot's own update)
    public function sendBackup($file = false)
    {
        require __DIR__ . '/config.php';
        $conf = $this->getPacConf();
        $json = $this->export();
        if (!empty($file)) {
            file_put_contents($file, $json);
        }
        if (empty($conf['backup_password'])) {
            $this->send($c['admin'][0], 'backup not sent: set a backup password in Settings, backups are only sent encrypted');
            return;
        }
        $bot = preg_replace('~[\W]~iu', '_', $this->request('getMyName', [])['result']['name']);
        $this->sendFile($c['admin'][0], new CURLStringFile($this->encryptBackup($json, $conf['backup_password']), "{$bot}_backup_" . date('d_m_Y_H_i') . '.enc.json', 'application/json'));
    }

    public function backupPassword()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('prompt backup password'),
            $this->input['message_id'],
            reply: $this->i18n('backup password'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setBackupPassword',
            'args'           => [],
        ];
    }

    public function setBackupPassword($text)
    {
        $text = trim((string) $text);
        $c    = $this->getPacConf();
        if ($text === '-') {
            unset($c['backup_password']);
        } elseif (preg_match('~^[^\x00-\x1f\x7f]{8,128}$~uD', $text)) {
            $c['backup_password'] = $text;
        } else {
            $this->send($this->input['chat'], 'wrong password: 8-128 printable characters');
            return $this->menu('config');
        }
        $this->setPacConf($c);
        $this->menu('config');
    }

    /**
     * New commits in the bot's own repository (origin, e.g. botlight).
     * The host side update/update.sh runs "git fetch" every hour, so here
     * only the already fetched refs are read.
     */
    public function newCommits($limit = 10): array
    {
        exec('git -C / log --no-merges --format=%s -n ' . (int) $limit . ' HEAD..@{u} 2>/dev/null', $out);
        return array_values(array_filter(array_map('trim', $out)));
    }

    public function changelog()
    {
        $commits = $this->newCommits(30);
        $text    = $commits
            ? "New in " . exec('git -C / rev-parse --abbrev-ref @{u} 2>/dev/null') . ":\n\n- " . implode("\n- ", array_map(fn($e) => htmlspecialchars($e), $commits))
            : 'no updates';
        $this->send($this->input['chat'], $text);
    }

    public function checkVersion()
    {
        try {
            require __DIR__ . '/config.php';
            if (!empty($c['admin']) && (empty($this->time) || ((time() - $this->time) > 3600))) {
                $this->time = time();
                $last       = trim(exec('git -C / rev-parse @{u} 2>/dev/null'));
                $commits    = $this->newCommits();
                if (!empty($last) && !empty($commits) && $last != $this->last) {
                    $this->last = $last;
                    $current    = trim(exec('git -C / show HEAD:VERSION 2>/dev/null'));
                    $new        = trim(exec('git -C / show @{u}:VERSION 2>/dev/null'));
                    $title      = $new && $new != $current ? "v$current → v$new\n" : '';
                    foreach ($c['admin'] as $k => $v) {
                        $this->send($v, $title . "- " . implode("\n- ", array_map(fn($e) => htmlspecialchars($e), $commits)), 0, [
                            [
                                [
                                    'text'          => $this->i18n('changelog'),
                                    'callback_data' => "/changelog",
                                ],
                                [
                                    'text'          => $this->i18n('update bot'),
                                    'callback_data' => "/applyupdatebot",
                                ],
                            ]
                        ]);
                    }
                    if ($this->getPacConf()['autoupdate']) {
                        $this->input['chat'] = $this->input['from'] = $c['admin'][0];
                        $this->applyupdatebot();
                    }
                }
            }
        } catch (Exception $e) {
        }
    }

    public function checkCert()
    {
        try {
            require __DIR__ . '/config.php';
            if (!empty($c['admin']) && date('H') == 12 && (empty($this->time2) || ((time() - $this->time2) > 4600))) {
                $this->time2 = time();
                $cert = $this->expireCert();
                if (!empty($cert) && $cert - 60 * 60 * 24 * 14 < time()) {
                    foreach ($c['admin'] as $k => $v) {
                        $this->send($v, "certificate expire: " . date('Y-m-d H:i:s', $cert));
                    }
                }
            }
        } catch (Exception $e) {
        }
    }

    public function getTime(int $seconds)
    {
        $seconds = ($seconds - time()) > 0 ? $seconds - time() : 0;
        $items   = [
            'Y' => [
                'diff' => 1970,
                'sign' => 'y',
            ],
            'm' => [
                'diff' => 1,
                'sign' => 'mon',
            ],
            'd' => [
                'diff' => 1,
                'sign' => 'd',
            ],
            'H' => [
                'diff' => 0,
                'sign' => 'h',
            ],
            'i' => [
                'diff' => 0,
                'sign' => 'min',
            ],
            's' => [
                'diff' => 0,
                'sign' => 's',
            ],
        ];
        $text = '';
        foreach ($items as $k => $v) {
            if (($t = gmdate($k, $seconds) - $v['diff']) > 0) {
                $text .= " $t{$v['sign']}";
                if (!empty($i)) {
                    break;
                }
                $i++;
            }
        }
        return trim($text) ?: '♾';
    }


    public function export()
    {
        $conf = [
            'ad'  => yaml_parse_file($this->adguard),
            'pac' => $this->getPacConf(),
            'ssl' => file_exists('/certs/cert_private') && preg_match('~BEGIN PRIVATE KEY~', file_get_contents('/certs/cert_private')) ? [
                'private' => file_get_contents('/certs/cert_private'),
                'public'  => file_get_contents('/certs/cert_public'),
            ] : false,
            'dnstt' => file_exists('/config/dnstt/server.key') ? [
                'private' => file_get_contents('/config/dnstt/server.key'),
                'public'  => file_get_contents('/config/dnstt/server.pub'),
            ] : false,
            'xray'          => $this->getXray(),
            'oc'            => file_get_contents('/config/ocserv.conf'),
            'ocu'           => file_get_contents('/config/ocserv.passwd'),
            'xraystats'     => $this->getXrayStats(),
        ];
        return json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    public function import()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('send the export file:'),
            $this->input['message_id'],
            reply: $this->i18n('send the export file:'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'importFromChat',
            'args'           => [],
        ];
    }

    // reply to the "send the backup" prompt: the file comes from the message,
    // the typed text (if any) is ignored
    public function importFromChat($text = '')
    {
        if (empty($this->input['file_id'])) {
            $this->send($this->input['chat'], 'send the backup as a file');
            return;
        }
        $this->importFile();
    }

    // reply with the password for an encrypted backup ($fileId from the prompt)
    public function importWithPassword($text, $fileId)
    {
        $this->input['file_id'] = $fileId;
        $this->importFile(false, trim((string) $text));
    }

    public function importFile($file = false, $password = null)
    {
        if (!empty($file)) {
            $json = json_decode(file_get_contents($file), true);
        } else {
            $r    = $this->request('getFile', ['file_id' => $this->input['file_id']]);
            $json = json_decode(file_get_contents($this->file . $r['result']['file_path']), true);
        }
        if (is_array($json) && !empty($json['vpnbot_backup'])) {
            // encrypted: the password set on this server, else the one typed
            $pass  = $password ?? ($this->getPacConf()['backup_password'] ?? '');
            $plain = $pass !== '' ? $this->decryptBackup($json, $pass) : null;
            if ($plain === null) {
                if ($password !== null) {
                    $this->send($this->input['chat'], 'wrong backup password');
                }
                $r = $this->send(
                    $this->input['chat'],
                    "@{$this->input['username']} " . $this->i18n('backup password'),
                    $this->input['message_id'],
                    reply: $this->i18n('backup password'),
                );
                $_SESSION['reply'][$r['result']['message_id']] = [
                    'start_message'  => $this->input['message_id'],
                    'start_callback' => $this->input['callback_id'],
                    'callback'       => 'importWithPassword',
                    'args'           => [$this->input['file_id']],
                ];
                return;
            }
            $json = json_decode($plain, true);
        }
        if (empty($json) || !is_array($json)) {
            $this->answer($this->input['callback_id'], 'error', true);
        } else {
            // certs
            if (!empty($json['ssl'])) {
                $out[] = 'update certificates';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                file_put_contents('/certs/cert_private', $json['ssl']['private']);
                file_put_contents('/certs/cert_public', $json['ssl']['public']);
            }
            // pac
            if (!empty($json['pac'])) {
                $out[] = 'update pac';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->setPacConf($json['pac']);
            }
            // ad
            if (!empty($json['ad'])) {
                $out[] = 'update adguard';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->stopAd();
                yaml_emit_file($this->adguard, $json['ad']);
                $this->startAd();
            }
            // xray
            if (!empty($json['xray'])) {
                $out[] = 'update xray';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->restartXray($json['xray']);
                $this->adguardXrayClients();
                $this->setUpstreamDomain($json['pac']['transport'] != 'Reality' ? 't' : ($json['pac']['reality']['domain'] ?: $json['xray']['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]));
            }
            // xraystats
            if (!empty($json['xraystats'])) {
                $out[] = 'update xray stats';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                // Xray was restarted by this import: what the old process
                // counted ("session") belongs to the totals now
                $st = $this->sessionToGlobal((array) $json['xraystats']);
                unset($st['xray_uptime']);
                $this->setXrayStats($st);
            }
            // ocserv
            if (!empty($json['oc'])) {
                $out[] = 'update ocserv';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                file_put_contents('/config/ocserv.passwd', $json['ocu']);
                $this->restartOcserv($json['oc']);
            }
            if (!empty($json['pac']['domain'])) {
                $this->setUpstreamDomainOcserv($json['pac']['domain']);
            }
            // dnstt
            if (!empty($json['dnstt'])) {
                $out[] = 'update dnstt certificates';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                file_put_contents('/config/dnstt/server.key', $json['dnstt']['private']);
                file_put_contents('/config/dnstt/server.pub', $json['dnstt']['public']);
            }
            // nginx
            $out[] = 'reset nginx';
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));

            $this->cloakNginx();

            $out[] = "end import";
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
            $this->language = $this->getPacConf()['language'] ?: 'en';
            $this->limit    = $this->getPacConf()['limitpage'] ?: 5;
            if (empty($file)) {
                sleep(3);
                $this->menu();
            }
        }
    }


    public function qrXray($i, $s = false)
    {
        $link    = $this->linkXray($i, $s);
        $qr_file = __DIR__ . "/qr/xray.png";
        exec('qrencode -t png -o ' . escapeshellarg($qr_file) . ' ' . escapeshellarg($link));
        $r = $this->sendPhoto(
            $this->input['chat'],
            curl_file_create($qr_file),
            "<code>$link</code>"
        );
        unlink($qr_file);
    }

    public function upload($name, $code, $chat = false)
    {
        return $this->sendFile($chat ?: $this->input['chat'], new CURLStringFile($code, $name));
    }

    public function reply()
    {
        if (!empty($_SESSION['reply'][$this->input['reply']])) {
            $this->delete($this->input['chat'], $this->input['reply']);
            $this->delete($this->input['chat'], $this->input['message_id']);
            $callback = $_SESSION['reply'][$this->input['reply']]['callback'];
            $this->input['message_id'] = $this->input['callback_id'] = $_SESSION['reply'][$this->input['reply']]['start_message'];
            $this->{$callback}($this->input['message'], ...$_SESSION['reply'][$this->input['reply']]['args']);
            $this->answer($_SESSION['reply'][$this->input['reply']]['start_message']);
            unset($_SESSION['reply'][$this->input['reply']]);
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
        }
        if (empty($nomenu)) {
            sleep(3);
            $this->menu('config');
        }
    }

    public function sslip()
    {
        require __DIR__ . '/config.php';
        $p  = $this->getPacConf();
        $ip = $this->ip;
        $r  = $this->send($c['admin'][0], "start $ip");

        $this->input['chat']        = $c['admin'][0];
        $this->input['message_id']  = $r['result']['message_id'];
        $this->input['callback_id'] = false;
        if (empty($p)) {
            $this->addDomain(str_replace('.', '-', $this->ip) . '.nip.io', 1);
            $this->setSSL('letsencrypt');
        }
        $this->menu();
    }

    public function uncomment($text, $tag)
    {
        $text = explode("\n", $text);
        foreach ($text as $k => $v) {
            if (preg_match("~#-$tag~", $v)) {
                $text[$k] = "##$tag";
                continue;
            }
            $text[$k] = preg_replace('~#~', '', $v, 1);
        }
        return implode("\n", $text);
    }

    public function deleteSSL($notmenu = false)
    {
        unlink('/certs/cert_private');
        unlink('/certs/cert_public');
        $conf = $this->getPacConf();
        unset($conf['letsencrypt']);
        $this->setPacConf($conf);
        $this->adguardSync();
        $this->cloakNginx();
        if (!$notmenu) {
            $this->menu('config');
        }
    }

    public function setSSL($name)
    {
        $conf = $this->getPacConf();
        switch ($name) {
            case 'letsencrypt':
                $out[] = 'Install certificate:';
                $this->update($this->input['chat'], $this->input['message_id'], htmlspecialchars(implode("\n", $out)));
                $oc      = $this->getHashSubdomain('oc');
                $domains = array_filter([
                    $conf['domain'],
                    $oc ? "$oc.{$conf['domain']}" : '',
                    $conf['adguardkey'] ? "{$conf['adguardkey']}.{$conf['domain']}" : '',
                ]);
                $args = implode(' ', array_map(fn($e) => '-d ' . escapeshellarg($e), $domains));
                exec("certbot certonly --force-renew --preferred-chain 'ISRG Root X1' -n --agree-tos --email " . escapeshellarg("mail@{$conf['domain']}") . " $args --webroot -w /certs/ --logs-dir /logs --max-log-backups 0 2>&1", $out, $code);
                if ($code > 0) {
                    $this->send($this->input['chat'], "ERROR\n" . htmlspecialchars(implode("\n", $out)));
                    break;
                }
                $out[] = 'Generate bundle';
                $this->update($this->input['chat'], $this->input['message_id'], htmlspecialchars(implode("\n", $out)));
                $bundle = file_get_contents("/etc/letsencrypt/live/{$conf['domain']}/privkey.pem") . file_get_contents("/etc/letsencrypt/live/{$conf['domain']}/fullchain.pem");
                $conf['letsencrypt'] = 'letsencrypt';
                break;
            case 'self':
                $r      = $this->request('getFile', ['file_id' => $this->input['file_id']]);
                $bundle = file_get_contents($this->file . $r['result']['file_path']);
                $conf['letsencrypt'] = 'self';
                break;
        }
        if (preg_match('~[^\s]+BEGIN PRIVATE KEY.+?END PRIVATE KEY[^\s]+~s', $bundle, $m)) {
            $this->setPacConf($conf);
            file_put_contents('/certs/cert_private', $m[0]);
            file_put_contents('/certs/cert_public', preg_replace('~[^\s]+BEGIN PRIVATE KEY.+?END PRIVATE KEY[^\s]+~s', '', $bundle));
            $this->adguardSync();
            $this->cloakNginx();
        } else {
            $this->update($this->input['chat'], $this->input['message_id'], "wrong format key");
        }
        sleep(3);
        $this->menu('config');
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

    public function getPacConf()
    {
        return json_decode(file_get_contents($this->pac), true);
    }

    public function setPacConf(array $conf)
    {
        return file_put_contents($this->pac, json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    public function domain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter domain'),
            $this->input['message_id'],
            reply: $this->i18n('enter domain'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addDomain',
            'args'          => [],
        ];
    }

    public function selfssl()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('prompt selfssl'),
            $this->input['message_id'],
            reply: $this->i18n('send file with your certificate chain and private key'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'selfsslInstall',
            'args'          => [],
        ];
    }

    public function adguardSync()
    {
        $pac = $this->getPacConf();
        $pac['adpswd'] = $pac['adpswd'] ?: bin2hex(random_bytes(8));
        $this->setPacConf($pac);
        $ssl = $this->nginxGetTypeCert();
        $c   = yaml_parse_file($this->adguard);
        $this->stopAd();
        $c['users'][0]['password'] = password_hash($pac['adpswd'], PASSWORD_DEFAULT);
        if (!empty($ssl) && !empty($pac['domain']) && empty($c['tls']['enabled'])) {
            $c['tls']['enabled']     = true;
            $c['tls']['server_name'] = $pac['domain'];
        }
        yaml_emit_file($this->adguard, $c);
        $this->startAd();
    }

    public function adguardpsswd()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter password'),
            $this->input['message_id'],
            reply: $this->i18n('enter password'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'chpsswd',
            'args'          => [],
        ];
    }

    public function setAdguardKey()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter key'),
            $this->input['message_id'],
            reply: $this->i18n('enter key'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setAdKey',
            'args'          => [],
        ];
    }


    public function setAdKey($key)
    {
        // used as a subdomain (DoT client id) in nginx/certbot/AdGuard configs
        if (!preg_match('~^[a-z0-9-]{1,63}$~D', $key = strtolower(trim((string) $key)))) {
            $this->send($this->input['chat'], 'wrong key: a-z, 0-9, -');
            return;
        }
        $c = $this->getPacConf();
        $c['adguardkey'] = $key;
        $this->setPacConf($c);
        $this->menu('adguard');
    }

    public function enterAdmin()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter id / name'),
            $this->input['message_id'],
            reply: $this->i18n('ph: enter id / name'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addAdmin',
            'args'          => [],
        ];
    }

    public function setIpLimit()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter seconds and count ip'),
            $this->input['message_id'],
            reply: $this->i18n('enter seconds:count_ip'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'switchIpLimit',
            'args'          => [],
        ];
    }

    public function addLinkDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter domain for link'),
            $this->input['message_id'],
            reply: $this->i18n('enter domain for link'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setLinkDomain',
            'args'          => [],
        ];
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

    public function enterPage()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter limit on page'),
            $this->input['message_id'],
            reply: $this->i18n('enter limit on page'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setPage',
            'args'          => [],
        ];
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

    // admins and their names live in config.php ($c['admin'], $c['admin_names'])
    public function adminConfig(): array
    {
        $file = __DIR__ . '/config.php';
        opcache_invalidate($file);
        require $file;
        $c['admin']       = array_values(array_map('intval', (array) ($c['admin'] ?? [])));
        $c['admin_names'] = (array) ($c['admin_names'] ?? []);
        return $c;
    }

    public function saveAdminConfig(array $c)
    {
        $file = __DIR__ . '/config.php';
        file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        opcache_invalidate($file);
    }

    // the name; the id until a name is set (admins added before names)
    public function adminLabel(array $c, int $id): string
    {
        $name = (string) ($c['admin_names'][$id] ?? '');
        return $name !== '' ? $name : (string) $id;
    }

    // "id / name": a Telegram user id (digits) and a name
    public function addAdmin($text)
    {
        if (!preg_match('~^\s*(\d{1,20})\s*/\s*(.+?)\s*$~uD', (string) $text, $m) || !$this->validName($m[2])) {
            $this->send($this->input['chat'], 'wrong format: id / name, like 123456789 / Pete (name: letters, digits, emoji, space . _ @ -)');
            return;
        }
        $c = $this->adminConfig();
        if (!in_array((int) $m[1], $c['admin'], true)) {
            $c['admin'][] = (int) $m[1];
        }
        $c['admin_names'][(int) $m[1]] = $m[2];
        $this->saveAdminConfig($c);
        $this->menu('config');
    }

    public function adminCard($id)
    {
        $c = $this->adminConfig();
        $k = array_search((int) $id, $c['admin'], true);
        if ($k === false) {
            return $this->menu('config');
        }
        $text   = $this->i18n('Menu') . ' -> ' . $this->i18n('config') . ' -> ' . $this->i18n('admin card');
        $text  .= "\nid: <code>$id</code>";
        $text  .= "\n" . $this->i18n('name') . ': ' . htmlspecialchars((string) ($c['admin_names'][(int) $id] ?? '—'));
        if ($k === 0) {
            $text .= "\n👑 " . $this->i18n('main admin: cannot be removed');
        }
        $row = [[
            'text'          => $this->i18n('rename'),
            'callback_data' => "/renameAdmin $id",
        ]];
        // the main admin (the first one, who started the bot) stays
        if ($k !== 0) {
            $row[] = [
                'text'          => $this->i18n('delete'),
                'callback_data' => "/deladmin $id",
            ];
        }
        $this->update($this->input['chat'], $this->input['message_id'], $text, [
            $row,
            [[
                'text'          => $this->i18n('back'),
                'callback_data' => '/menu config',
            ]],
        ]);
    }

    public function renameAdmin($id)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter name'),
            $this->input['message_id'],
            reply: $this->i18n('enter name'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setAdminName',
            'args'           => [(int) $id],
        ];
    }

    public function setAdminName($name, $id)
    {
        $c = $this->adminConfig();
        if (!in_array((int) $id, $c['admin'], true)) {
            return $this->menu('config');
        }
        if (!$this->validName($name = trim((string) $name))) {
            $this->send($this->input['chat'], 'wrong name: letters, digits, emoji, space . _ @ -');
            return $this->adminCard($id);
        }
        $c['admin_names'][(int) $id] = $name;
        $this->saveAdminConfig($c);
        $this->adminCard($id);
    }

    public function delAdmin($id)
    {
        $c = $this->adminConfig();
        $k = array_search((int) $id, $c['admin'], true);
        // never the main admin (the first one): the bot always keeps an
        // admin, with none left the next person to write to it would become
        // admin
        if ($k === false || $k === 0) {
            $this->answer($this->input['callback_id'], $k === false ? 'no such admin' : 'the main admin cannot be removed', true);
            return;
        }
        unset($c['admin'][$k], $c['admin_names'][(int) $id]);
        $c['admin'] = array_values($c['admin']);
        $this->saveAdminConfig($c);
        $this->menu('config');
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
        $c = yaml_parse_file($this->adguard);
        $c['users'][0]['password'] = password_hash($pass, PASSWORD_DEFAULT);
        yaml_emit_file($this->adguard, $c);
        $p = $this->getPacConf();
        $p['adpswd'] = $pass;
        $this->setPacConf($p);
        $out[] = $this->startAd();
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        sleep(3);
        $this->menu('adguard');
    }

    public function adguardreset()
    {
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        // restore the default config from the repo; /.git is mounted read-only
        $default = shell_exec('git -C / show HEAD:config/AdGuardHome.yaml');
        if (!empty($default)) {
            file_put_contents('/config/AdGuardHome.yaml', $default);
        }
        $this->adguardSync();
        $this->cloakNginx();
        sleep(3);
        $this->menu('adguard');
    }

    public function adguardXrayClients()
    {
        $xr = $this->getXray();
        $ad = yaml_parse_file($this->adguard);
        foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
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
        }
        $ad['clients']['persistent'] = $tmp;
        yaml_emit_file($this->adguard, $ad);
        $this->stopAd();
        $this->startAd();
    }

    public function checkdns()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('prompt checkdns'),
            $this->input['message_id'],
            reply: $this->i18n('enter command'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'dnscheck',
            'args'          => [],
        ];
    }

    public function dnscheck($dns)
    {
        exec('JSON=1 dnslookup ' . implode(' ', array_map('escapeshellarg', preg_split('~\s+~', trim($dns)))), $out, $code);
        if ($code) {
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out), mode: false);
        } else {
            $this->send($this->input['chat'], "JSON=1 dnslookup $dns\n" . implode("\n", $out), mode: false);
        }
        sleep(3);
        $this->menu('adguard');
    }

    public function addupstream()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter address upstream'),
            $this->input['message_id'],
            reply: $this->i18n('ph: enter address upstream'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'upstream',
            'args'          => [],
        ];
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
        $c = yaml_parse_file($this->adguard);
        $c['dns']['upstream_dns'][] = $url;
        yaml_emit_file($this->adguard, $c);
        $out[] = $this->startAd();
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        sleep(3);
        $this->menu('adguard');
    }

    public function delupstream($k)
    {
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $this->stopAd();
        $c = yaml_parse_file($this->adguard);
        unset($c['dns']['upstream_dns'][$k]);
        $c['dns']['upstream_dns'] = array_values($c['dns']['upstream_dns']);
        yaml_emit_file($this->adguard, $c);
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

    public function startAd()
    {
        return $this->ssh('/opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work', 'ad', false);
    }

    public function stopAd()
    {
        return $this->ssh('kill -15 $(cat /opt/adguardhome/pid)', 'ad');
    }

    public function selfsslInstall()
    {
        $this->setSSL('self');
    }

    public function include($type)
    {
        switch ($type) {
            case 'rulessetlist':
                $r = $this->send(
                    $this->input['chat'],
                    "@{$this->input['username']} " . $this->i18n('prompt rulesset'),
                    $this->input['message_id'],
                    reply: 'outbound[:behavior]:time:URL',
                );
                break;

            default:
                $r = $this->send(
                    $this->input['chat'],
                    "@{$this->input['username']} " . $this->i18n('list separated by commas'),
                    $this->input['message_id'],
                    reply: $this->i18n('ph: list separated by commas'),
                );
                break;
        }
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addInclude',
            'args'          => [$type],
        ];
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
            $conf = $this->getPacConf();
            foreach ($domains as $k => $v) {
                if (in_array($type, ['white', 'deny'])) {
                    $conf[$type][] = $v;
                } else {
                    $conf[$type][$type == 'rulessetlist' ? trim($v) : idn_to_ascii(trim($v))] = true;
                }
            }
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
        if (!empty($c['blocklist']) && !empty(array_filter($c['blocklist']))) {
            $domains = array_keys(array_filter($c['blocklist'], function ($v, $k){
                    if (!empty($v)) {
                        if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                            return true;
                        }
                    }
                    return false;
                }, ARRAY_FILTER_USE_BOTH));
            if (!empty($domains)) {
                $rules[] = [
                    "type"        => "field",
                    "outboundTag" => "block",
                    "domain"      => array_keys(array_filter($c['blocklist'], function ($v, $k){
                        if (!empty($v)) {
                            if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                                return true;
                            }
                        }
                        return false;
                    }, ARRAY_FILTER_USE_BOTH)),
                ];
            }
        }
        if (!empty($c['blocklist']) && !empty(array_filter($c['blocklist']))) {
            $ips = array_keys(array_filter($c['blocklist'], function ($v, $k){
                    if (!empty($v)) {
                        if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                            return true;
                        }
                    }
                    return false;
                }, ARRAY_FILTER_USE_BOTH));
            if (!empty($ips)) {
                $rules[] = [
                    "type"        => "field",
                    "outboundTag" => "block",
                    "ip"          => array_keys(array_filter($c['blocklist'], function ($v, $k){
                        if (!empty($v)) {
                            if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                                return true;
                            }
                        }
                        return false;
                    }, ARRAY_FILTER_USE_BOTH)),
                ];
            }
        }
        if (!empty($c['warplist']) && !empty(array_filter($c['warplist']))) {
            $domains = array_keys(array_filter($c['warplist'], function ($v, $k){
                    if (!empty($v)) {
                        if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                            return true;
                        }
                    }
                    return false;
                }, ARRAY_FILTER_USE_BOTH));
            if (!empty($domains)) {
                $rules[] = [
                    "type"        => "field",
                    "outboundTag" => "warp",
                    "domain"      => array_keys(array_filter($c['warplist'], function ($v, $k){
                        if (!empty($v)) {
                            if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                                return true;
                            }
                        }
                        return false;
                    }, ARRAY_FILTER_USE_BOTH)),
                ];
            }
        }
        if (!empty($c['warplist']) && !empty(array_filter($c['warplist']))) {
            $ips = array_keys(array_filter($c['warplist'], function ($v, $k){
                    if (!empty($v)) {
                        if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                            return true;
                        }
                    }
                    return false;
                }, ARRAY_FILTER_USE_BOTH));
            if (!empty($ips)) {
                $rules[] = [
                    "type"        => "field",
                    "outboundTag" => "warp",
                    "ip"          => array_keys(array_filter($c['warplist'], function ($v, $k){
                        if (!empty($v)) {
                            if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                                return true;
                            }
                        }
                        return false;
                    }, ARRAY_FILTER_USE_BOTH)),
                ];
            }
        }
        $xr['routing']['rules'] = $rules ?: [];
        $this->restartXray($xr);
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
                        'callback_data' => "/change$type " . ($i + $page * $this->limit) . " $page",
                    ],
                    [
                        'text'          => $this->i18n('delete'),
                        'callback_data' => "/delete$type " . ($i + $page * $this->limit) . " $page",
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
        return [$data, $text];
    }

    public function listPacChange($type, $action, $key, $page = 0)
    {
        $conf = $this->getPacConf();
        $i = 0;
        foreach ($conf[$type] as $k => $v) {
            if ($key == $i) {
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
            $i++;
        }
        $this->setPacConf($conf);
        $this->backXtlsList($type, $page);
    }


    public function i18n(string $menu): string
    {
        return $this->i18n[$menu][$this->language] ?: $menu;
    }

    public function alignColumns(array $columns): string
    {
        // Находим максимальную длину для каждого столбца
        $columnLengths = [];
        foreach ($columns as $column) {
            $maxLength = 0;
            foreach ($column as $cell) {
                $len = mb_strlen($cell, 'UTF-8');
                $maxLength = max($maxLength, $len);
            }
            $columnLengths[] = $maxLength;
        }

        // Получаем количество строк из первого столбца
        $rowCount = count($columns[0]);
        $columnCount = count($columns);

        // Формируем строки с выравниванием
        $result = [];
        for ($row = 0; $row < $rowCount; $row++) {
            $line = '';
            for ($col = 0; $col < $columnCount; $col++) {
                $cell = $columns[$col][$row];
                $padding = str_repeat(' ', $columnLengths[$col] - mb_strlen($cell, 'UTF-8'));
                $line .= $cell . $padding;

                // Добавляем разделитель между столбцами, кроме последнего
                if ($col < $columnCount - 1) {
                    $line .= '  '; // Два пробела между столбцами
                }
            }
            $result[] = $line;
        }

        return implode("\n", $result);
    }

    public function dnsttDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter domain'),
            $this->input['message_id'],
            reply: $this->i18n('enter domain'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setdnsttDomain',
            'args'          => [],
        ];
    }

    public function dnsttPassword()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter password'),
            $this->input['message_id'],
            reply: $this->i18n('enter password'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setdnsttPassword',
            'args'          => [],
        ];
    }

    public function setdnsttPassword($text)
    {
        $c = $this->getPacConf();
        if ($text && !$this->validSecret($text = trim((string) $text))) {
            $this->send($this->input['chat'], 'wrong password: 1-128 printable characters, no ":"');
            return;
        }
        if ($text) {
            $c['dnsttPassword'] = $text;
        } else {
            unset($c['dnsttPassword']);
        }
        $this->setPacConf($c);
        $this->dnsttStart();
        $this->dnstt(true); // edits the DNSTT menu message
    }

    public function setdnsttDomain($text)
    {
        $c = $this->getPacConf();
        if ($text && !$this->validHost($text = trim((string) $text))) {
            $this->send($this->input['chat'], 'wrong domain');
            return;
        }
        if ($text) {
            $c['dnsttDomain'] = $text;
        } else {
            unset($c['dnsttDomain']);
        }
        $this->setPacConf($c);
        $this->dnsttStart();
        $this->dnstt(true); // edits the DNSTT menu message
    }

    public function dnsttStart()
    {
        $c = $this->getPacConf();
        $this->ssh('pkill dnstt', 'dnstt');
        // the domain goes into a background "sh -c" command: allow hostnames only
        if (!empty($c['dnsttDomain']) && !empty($c['dnsttPassword']) && preg_match('~^[A-Za-z0-9.-]{1,253}$~D', $c['dnsttDomain'])) {
            $this->ssh('echo ' . escapeshellarg("vpnbot:{$c['dnsttPassword']}") . ' | chpasswd', 'dnstt');
            if (!file_exists('/config/dnstt/server.key')) {
                $this->ssh("dnstt-server -gen-key -privkey-file /dnstt/server.key -pubkey-file /dnstt/server.pub", 'dnstt');
            }
            $this->ssh("dnstt-server -udp :53 -privkey-file /dnstt/server.key {$c['dnsttDomain']} 127.0.0.1:22", 'dnstt' , false, '/logs/dnstt');
        } else {
            // dnstt is off: the tunnel account must not keep an old password
            $this->ssh('passwd -l vpnbot', 'dnstt');
        }
    }

    public function dnsttDownload()
    {
        $this->sendFile($this->input['from'], curl_file_create('/config/dnstt/server.pub'));
    }

    public function dnstt($update = false)
    {
        $c      = $this->getPacConf();
        $pubkey = file_get_contents('/config/dnstt/server.pub');
        $text[] = "dnstt";
        if (!empty($c['dnsttDomain']) && !empty($c['dnsttPassword'])) {
            $text[] = "<pre>set the NS record for {$c['dnsttDomain']}: tns.{$c['domain']}\nset A record for tns.{$c['domain']}: {$this->ip}</pre>";
            $text[] = 'account: <code>vpnbot:' . htmlspecialchars($c['dnsttPassword']) . '</code>';
            $text[] = "server name: <code>{$c['dnsttDomain']}</code>";
            $text[] = "public key: <code>$pubkey</code>";
            $data[] = [
                [
                    'text'          => $this->i18n('download pubkey'),
                    'callback_data' => "/dnsttDownload",
                ],
            ];
        } else {
            $text[] = "set subdomain and password";
        }

        $data[] = [
            [
                'text'          => $this->i18n('set subdomain'),
                'callback_data' => "/dnsttDomain",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('set password'),
                'callback_data' => "/dnsttPassword",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        if ($update) {
            $this->update(
                $this->input['chat'],
                $this->input['message_id'],
                implode("\n", $text),
                $data ?: false,
            );
        } else {
            $this->send(
                $this->input['chat'],
                implode("\n", $text),
                $this->input['message_id'],
                $data ?: false,
            );
        }
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

    public function menu($type = false, $arg = false, $return = false)
    {
        $conf   = $this->getPacConf();
        $domain = $conf['domain'] ?: $this->ip;
        $hash   = $this->getHashBot();
        if ($type == false) {
            $update = exec('git -C / rev-list --count HEAD..@{u}');
            $branch = exec('git -C / rev-parse --abbrev-ref HEAD');
            $backup = array_filter(explode('/', $conf['backup'] ?? ''));
            if (!empty($backup)) {
                if (!empty(strtotime($backup[0])) && !empty(strtotime($backup[1]))) {
                    $backup = "{$backup[0]} start / {$backup[1]} period";
                } else {
                    $backup = "{$conf['backup']} - wrong format";
                }
            }
            $cron   = $this->dontshowcron ? '' : $this->i18n($this->ssh('pgrep -f cron.php', 'service') ? 'on' : 'off') . ' cron';
            $main[] = 'v' . getenv('VER') . " $branch" . ($update ? ' (have updates)' : '');

            if (!empty($conf['domain'])) {
                $main[] = '';
                $oc     = $this->getHashSubdomain('oc');
                if (!empty($conf['domain'])) {
                    $ssl_expiry = $this->expireCert();
                    $certs      = $this->domainsCert() ?: [];

                    $main[] = "<blockquote>";
                    $main[] = "Domains:";
                    $main[] = $conf['domain'] . (in_array($conf['domain'], $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
                    if (!empty($oc)) {
                        $main[] = 'openconnect ' . "$oc.{$conf['domain']}" . (in_array("$oc.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
                    }
                    if (!empty($conf['adguardkey'])) {
                        $main[] = "{$conf['adguardkey']}.{$conf['domain']}" . (in_array("{$conf['adguardkey']}.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '') . ' adguard DOT';
                    }
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
                $this->i18n($this->ssh('pgrep xray', 'xr') ? 'on' : 'off') . ' ' . $this->i18n('xray'),
                $this->i18n($this->ssh('pgrep ocserv', 'oc') ? 'on' : 'off') . ' ' . $this->i18n('ocserv'),
                $this->i18n($this->adguardUp() ? 'on' : 'off') . ' ' . $this->i18n('ad_title'),
            ];
            $portcol = [
                $this->i18n('on') . ' 443',
                $this->i18n('on') . ' 443',
                $this->i18n($ports['ad']['enable'] ? 'on' : 'off') . ($ports['ad']['enable'] ? ' ' . $ports['ad']['port'] : ' port is closed'),
            ];
            if ($dnstt) {
                $status[]  = $this->i18n($this->ssh('pgrep dnstt', 'dnstt') ? 'on' : 'off') . ' ' . $this->i18n('dnstt');
                $portcol[] = $this->i18n($ports['dnstt']['enable'] ? 'on' : 'off') . ($ports['dnstt']['enable'] ? ' ' . $ports['dnstt']['port'] : ' port is closed');
            }
            $status[]  = $this->i18n($this->cachedWarpStatus()) . ' ' . $this->i18n('warp');
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
                    $this->i18n($backup ? 'on' : 'off') . ' autobackup',
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
                'text' => implode("\n", $main ?: []),
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

        $text = $menu[$type ?: 'main' ]['text'];
        $data = $menu[$type ?: 'main' ]['data'];

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

    public function switchBanIp()
    {
        $c = $this->getPacConf();
        $c['autodeny'] = $c['autodeny'] ? 0 : 1;
        $this->setPacConf($c);
        $this->ipMenu();
    }

    public function switchMonthlyStats()
    {
        $c = $this->getPacConf();
        $c['reset_monthly'] = $c['reset_monthly'] ? 0 : 1;
        $this->setPacConf($c);
        $this->xray();
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
            $c['ip_count'] = (int) $limit[1] ?: 1;
        }
        $this->setPacConf($c);
        // the access log goes on/off with the limit
        $this->restartXray($this->getXray());
        if (empty($c['ip_limit'])) {
            @file_put_contents('/logs/xray', '');
        }
        $this->xray();
    }

    public function switchSilence()
    {
        $c = $this->getPacConf();
        $c['silence'] = (($c['silence'] ?: 0) + 1) % 3;
        $this->setPacConf($c);
        $this->ipMenu();
    }

    public function ipMenu()
    {
        $text   = $this->i18n('config') . ' -> ' . $this->i18n('IP & Logs');
        $pac    = $this->getPacConf();
        $d      = count($pac['deny'] ?: []);
        $w      = count($pac['white'] ?: []);
        $data[] = [
            [
                'text'          => $this->i18n('autoscan') . ': ' . ($pac['autoscan'] ? $this->getTime(strtotime(($pac['autoscan_timeout'] ?: 3600) . ' seconds')) : $this->i18n('off')),
                'callback_data' => '/autoScanTimeout',
            ],
        ];
        if (!empty($pac['autoscan'])) {
            $data[] = [
                [
                    'text'          => $this->i18n('autoblock') . ': ' . $this->i18n($pac['autodeny'] ? 'on' : 'off'),
                    'callback_data' => '/switchBanIp',
                ],
                [
                    'text'          => $this->i18n('notify') . ': ' . ((function ($pac) {
                        switch ($pac['silence']) {
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
        if ($r = fopen($file, 'r')) {
            while (feof($r) === false) {
                $l = fgets($r);
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)~', $l, $m)) {
                    if ($reverse xor preg_match($regexp, $l)) {
                        if (is_array($ranges)) {
                            $flag = true;
                            foreach ($ranges as $range) {
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

    public function analysisIp(int $page = 0, $return = false)
    {
        $pac = $this->getPacConf();
        $xr  = [];
        foreach (array_merge($pac['white'] ?: [], $pac['deny'] ?: [], ['10.10.0.0/23']) as $v) {
            if (preg_match('~^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:(/\d{1,2}))?$~', $v, $m)) {
                if (!in_array($m[1] . ($m[2] ?: '/32'), $xr)) {
                    $xr[] = $m[1] . ($m[2] ?: '/32');
                }
            }
        }
        if ($r = fopen('/logs/nginx_doh_access', 'r')) {
            while (feof($r) === false) {
                $l = fgets($r);
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)~', $l, $m)) {
                    if (!in_array("{$m[1]}/32", $xr)) {
                        $xr[] = "{$m[1]}/32";
                    }
                }
            }
            fclose($r);
        }
        if ($r = fopen('/logs/xray', 'r')) {
            while (feof($r) === false) {
                $l = fgets($r);
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)(?=.+accepted)~', $l, $m)) {
                    if (!in_array("{$m[1]}/32", $xr)) {
                        $xr[] = "{$m[1]}/32";
                    }
                }
            }
            fclose($r);
        }

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

        if (!empty($return)) {
            return $ip;
        }
        if (!empty($ip)) {
            foreach ($ip as $k => $v) {
                $data[] = [
                    [
                        'text'          => $k,
                        'callback_data' => "/searchLogs $k analysisIp $page 0",
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
                'text'          => $this->i18n('back'),
                'callback_data' => "/ipMenu",
            ],
        ];
        $this->update($this->input['from'], $this->input['message_id'], count($ip) ?: 'empty', $data);
    }

    public function searchLogs($search, $fun = false, $page = 0, $white = 0)
    {
        if (preg_match('~^\d+\.\d+\.\d+\.\d+$~D', $search)) {
            $info = file_get_contents("https://ipinfo.io/$search/json", context: stream_context_create(['http' => ['timeout' => 2]]));
            $text = "$search\n<pre>" . htmlspecialchars((string) $info) . "</pre>";
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
                        'callback_data' => "/$fun $page" . ($white ? " $white" : ''),
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

    public function searchIp($ip)
    {
        foreach ($this->logs as $v) {
            if ($r = fopen("/logs/$v", 'r')) {
                while (feof($r) === false) {
                    $l = fgets($r);
                    if (preg_match('~' . preg_quote($ip) . '~', $l)) {
                        $res[$v][] = $l;
                    }
                }
                fclose($r);
            }
        }
        if (!empty($res)) {
            foreach ($res as $k => $v) {
                $head= "$k:\n";
                $t = array_chunk($v, 10);
                foreach ($t as $j) {
                    $text = "$head<pre>";
                    foreach ($j as $i) {
                        $text .= htmlspecialchars($i, ENT_HTML5, 'UTF-8');
                    }
                    $text .= '</pre>';
                    $this->send($this->input['from'], $text, $this->input['message_id']);
                }
            }
        } else {
            $this->answer($this->input['callback_id'], 'empty');
        }
    }

    public function searchSuspiciousIp($ip)
    {
        $t = [
            $this->suspicious('~\d+\.\d+\.\d+\.\d+.+200\s\d+\s0$~', '/logs/upstream_access', "$ip/32", 'possibly a Reality Degenerate'),
            $this->suspicious($this->reg, '/logs/nginx_default_access', "$ip/32", 'possibly a scanner', true),
            $this->suspicious($this->reg, '/logs/nginx_domain_access', "$ip/32", 'possibly a scanner', true),
        ];
        foreach ($t as $r) {
            if (!empty($r)) {
                foreach ($r as $v) {
                    foreach ($v as $k) {
                        $logs[$k['title']][] = $k['log'];
                    }
                }
            }
        }
        if (!empty($logs)) {
            foreach ($logs as $k => $v) {
                $head= "$k:\n";
                $t = array_chunk($v, 10);
                foreach ($t as $j) {
                    $text = "$head<pre>";
                    foreach ($j as $i) {
                        $text .= htmlspecialchars($i, ENT_HTML5, 'UTF-8');
                    }
                    $text .= '</pre>';
                    $this->send($this->input['from'], $text, $this->input['message_id']);
                }
            }
        } else {
            $this->answer($this->input['callback_id'], 'empty');
        }
    }

    public function importIps($type)
    {
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
                        'callback_data' => "/searchLogs $v denyList $page $white",
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

    public function denyIp($ip, $fun = false, $page = 0, $white = 0)
    {
        $pac = $this->getPacConf();
        if (is_array($ip)) {
            foreach ($ip as $v) {
                $pac['deny'][] = $v;
                if (($t = array_search($v, $pac['white'] ?: [])) !== false) {
                    unset($pac['white'][$t]);
                }
            }
        } else {
            $pac['deny'][] = $ip;
            if (($t = array_search($ip, $pac['white'] ?: [])) !== false) {
                unset($pac['white'][$t]);
            }
        }
        $this->setPacConf($pac);
        if (empty($fun)) {
            $this->delete($this->input['from'], $this->input['message_id']);
        }
        $this->syncDeny();
        if (!empty($fun)) {
            $this->{$fun}($page, $white);
        }
    }

    public function whiteIp($ip, $fun = false, $page = 0, $white = 0)
    {
        $pac = $this->getPacConf();
        if (is_array($ip)) {
            foreach ($ip as $v) {
                $pac['white'][] = $v;
                if (($t = array_search($v, $pac['deny'] ?: [])) !== false) {
                    unset($pac['deny'][$t]);
                }
            }
        } else {
            $pac['white'][] = $ip;
            if (($t = array_search($ip, $pac['deny'] ?: [])) !== false) {
                unset($pac['deny'][$t]);
            }
        }
        $this->setPacConf($pac);
        if (empty($fun)) {
            $this->delete($this->input['from'], $this->input['message_id']);
        }
        $this->syncDeny();
        if (!empty($fun)) {
            $this->{$fun}($page, $white);
        }
    }

    public function allowIp($ip, $page, $white = 0)
    {
        $pac = $this->getPacConf();
        unset($pac[$white ? 'white' : 'deny'][array_search($ip, $pac[$white ? 'white' : 'deny'])]);
        $this->setPacConf($pac);
        $this->syncDeny();
        $this->denyList($page, $white);
    }

    public function cleanLogs($ip, $nodelete = false)
    {
        // drop lines containing $ip without passing it to a shell
        foreach ($this->logs as $v) {
            $f = "/logs/$v";
            if (is_file($f) && $ip !== '') {
                $lines = file($f) ?: [];
                file_put_contents($f, implode('', array_filter($lines, fn($l) => strpos($l, $ip) === false)));
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
        $pac['white'] = array_values(array_filter($pac['white'] ?: [], [$this, 'validIpOrCidr']));
        $pac['deny']  = array_values(array_filter($pac['deny'] ?: [], [$this, 'validIpOrCidr']));
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
                if (!in_array($v, $pac['white'] ?: [])) {
                    $text .= "deny $v;\n";
                } else {
                    unset($pac['deny'][$k]);
                }
            }
        }
        $this->setPacConf($pac);
        file_put_contents('/config/deny', $text ?: '');
        $this->ssh('nginx -s reload', 'up');
    }

    public function linkXray($i, $s = false)
    {
        $c      = $this->getXray();
        $pac    = $this->getPacConf();
        $domain = $this->getDomain($pac['transport'] != 'Reality');
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();
        $si     = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'si',
            's' => $c['inbounds'][0]['settings']['clients'][$i]['id'],
        ]));

        switch ($s) {
            case 2:
                return "sing-box://import-remote-profile/?url={$si}#" . rawurlencode((string) $c['inbounds'][0]['settings']['clients'][$i]['email']);

            default:
                switch ($pac['transport']) {
                    case 'Reality':
                        $link = "vless://{$c['inbounds'][0]['settings']['clients'][$i]['id']}@$domain:443"
                                    . "?security=reality"
                                    . "&sni={$c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]}"
                                    . "&fp=chrome&pbk={$pac['xray']}"
                                    . "&sid={$c['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0]}"
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
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('prompt bridge'),
            $this->input['message_id'],
            reply: $this->i18n('bridge IP'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setBridge',
            'args'           => [],
        ];
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

    public function ocMenu()
    {
        $pac    = $this->getPacConf();
        $domain = $this->getDomain();
        $ocserv = file_get_contents('/config/ocserv.conf');
        preg_match('~^camouflage_secret[^\n]+?"([^"]+)*"~sm', $ocserv, $m);
        $cs = $m[1];
        $pass   = htmlspecialchars((string) ($pac['ocserv'] ?? ''));
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('ocserv');
        if (!empty($cs)) {
            $oc = $this->getHashSubdomain('oc');
            $text[] = "<code>https://$oc.$domain/?" . htmlspecialchars((string) $cs) . "</code>";
        }
        $text[] = "password: <span class='tg-spoiler'>$pass</span>";
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
        ];
        $clients = $this->getClientsOc();
        foreach ($clients as $k => $v) {
            $data[] = [
                [
                    'text'          => $v,
                    'callback_data' => "/ocUser $k",
                ],
                [
                    'text'          => $this->i18n('delete'),
                    'callback_data' => "/deloc $k",
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


    public function ocUser(int $i)
    {
        $clients = $this->getClientsOc();
        if (!isset($clients[$i])) {
            return $this->menu('oc');
        }
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $this->i18n('Menu') . ' -> ' . $this->i18n('ocserv') . ' -> ' . htmlspecialchars($clients[$i]),
            [
                [
                    [
                        'text'          => $this->i18n('rename'),
                        'callback_data' => "/renameOcUser $i",
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

    public function renameOcUser(int $i)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter name'),
            $this->input['message_id'],
            reply: $this->i18n('enter name'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'renOcUs',
            'args'           => [$i],
        ];
    }

    // all OpenConnect users share one password: the new name gets it, the old one is removed
    public function renOcUs($name, $i)
    {
        $clients = $this->getClientsOc();
        if (!isset($clients[$i])) {
            return $this->menu('oc');
        }
        if (!preg_match('~^[A-Za-z0-9._@-]{1,64}$~D', $name = trim((string) $name))) {
            $this->send($this->input['chat'], 'wrong name: A-Z a-z 0-9 . _ @ -');
            return $this->ocUser($i);
        }
        if ($name === $clients[$i]) {
            return $this->ocUser($i);
        }
        if (in_array($name, $clients, true)) {
            $this->send($this->input['chat'], "user $name already exists");
            return $this->ocUser($i);
        }
        $pac = $this->getPacConf();
        $this->ssh('echo ' . escapeshellarg((string) ($pac['ocserv'] ?? '')) . ' | ocpasswd -c /etc/ocserv/ocserv.passwd ' . escapeshellarg($name), 'oc');
        $this->ssh('ocpasswd -c /etc/ocserv/ocserv.passwd -d ' . escapeshellarg($clients[$i]), 'oc');
        $k = array_search($name, $this->getClientsOc(), true);
        return $k === false ? $this->menu('oc') : $this->ocUser((int) $k);
    }

    public function deloc($i)
    {
        $clients = $this->getClientsOc();
        foreach ($clients as $k => $v) {
            if ($i == $k) {
                $this->ssh('ocpasswd -c /etc/ocserv/ocserv.passwd -d ' . escapeshellarg($v), 'oc');
                break;
            }
        }
        $this->menu('oc');
    }

    public function delxr($i)
    {
        $r  = $this->getXray();
        foreach ($r['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($i == $k) {
                // its traffic leaves the stats in restartXray (by name)
                unset($r['inbounds'][0]['settings']['clients'][$k]);
                $this->restartXray($r);
                $this->adguardXrayClients();
                break;
            }
        }
        $this->xray();
    }

    public function getClientsOc()
    {
        $users = array_filter(explode("\n", file_get_contents('/config/ocserv.passwd')), fn ($e) => !empty($e));
        return array_map(fn($e) => explode(':', $e)[0], $users);
    }

    public function addocus($user)
    {
        // ocserv.passwd is "user:hash" lines
        if (!preg_match('~^[A-Za-z0-9._@-]{1,64}$~D', $user = trim((string) $user))) {
            $this->send($this->input['chat'], 'wrong name: A-Z a-z 0-9 . _ @ -');
            return;
        }
        $pac = $this->getPacConf();
        $this->ssh('echo ' . escapeshellarg($pac['ocserv']) . ' | ocpasswd -c /etc/ocserv/ocserv.passwd ' . escapeshellarg($user), 'oc');
        $this->menu('oc');
    }

    public function addxrus($users)
    {
        $c     = $this->getXray();
        $p     = $this->getPacConf();
        $users = array_map(fn ($e) => trim($e), explode(',', $users));
        $users = array_map(fn ($e) => explode(':', $e), $users);
        foreach ($c['inbounds'][0]['settings']['clients'] as $k => $v) {
            $uuids[]  = $v['id'];
            $emails[] = $v['email'];
        }
        foreach ($users as $user) {
            if (!$this->validName($user[0] ?? '') || (!empty($user[1]) && !preg_match('~^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$~iD', $user[1]))) {
                $this->send($this->input['chat'], 'wrong user: name[:uuid], name of letters, digits, emoji, space . _ @ -');
                return $this->xray();
            }
            $uuid = ($user[1] ?? '') ?: trim($this->ssh('xray uuid', 'xr'));
            if (in_array($uuid, $uuids ?: []) || in_array($user[0], $emails ?: [])) {
                $this->send($this->input['chat'], "user {$user[0]} already exists");
                return $this->xray();
            }
            $c['inbounds'][0]['settings']['clients'][] = $p['transport'] != 'Reality' ? [
                    'id'    => $uuid,
                    'email' => $user[0],
                ] : [
                    'id'    => $uuid,
                    'flow'  => 'xtls-rprx-vision',
                    'email' => $user[0],
            ];
        }
        $this->restartXray($c);
        $this->adguardXrayClients();
        if (count($users) == 1) {
            $this->userXr(count($c['inbounds'][0]['settings']['clients']) - 1);
        } else {
            $this->xray();
        }
    }


    public function switchXr($i, $nm = 0)
    {
        $c = $this->getXray();
        if (empty($c['inbounds'][0]['settings']['clients'][$i]['off'])) {
            $c['inbounds'][0]['settings']['clients'][$i]['off'] = $c['inbounds'][0]['settings']['clients'][$i]['id'];
            $c['inbounds'][0]['settings']['clients'][$i]['id']  = trim($this->ssh('xray uuid', 'xr'));
        } else {
            $c['inbounds'][0]['settings']['clients'][$i]['id'] = $c['inbounds'][0]['settings']['clients'][$i]['off'];
            unset($c['inbounds'][0]['settings']['clients'][$i]['off']);
        }
        $this->restartXray($c);
        if (empty($nm)) {
            $this->userXr($i);
        }
    }

    public function renXrUs($name, $i)
    {
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
        $this->restartXray($c, false, [$old, $name]);
        $this->adguardXrayClients();
        $this->userXr($i);
    }

    public function getXrayStats()
    {
        return json_decode(@file_get_contents('/config/xray.stats'), true) ?: [];
    }

    public function setXrayStats($x)
    {
        file_put_contents('/config/xray.stats', json_encode($x));
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

    public function resetXrStats($nomenu = false)
    {
        $this->restartXray($this->getXray());
        $this->updateXrayStats(fn($p) => []);
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

    public function templateAdd($type)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('send the template file:'),
            $this->input['message_id'],
            reply: $this->i18n('send the template file:'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addTemplate',
            'args'           => [$type],
        ];
    }

    public function autoScanTimeout()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('send time like 1 hour or 1 day etc'),
            $this->input['message_id'],
            reply: $this->i18n('ph: send time like 1 hour or 1 day etc'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setAutoScanTimeout',
            'args'           => [],
        ];
    }

    public function setAutoScanTimeout($time)
    {
        $pac = $this->getPacConf();
        if (empty($time)) {
            unset($pac['autoscan_timeout']);
            unset($pac['autoscan']);
        } elseif ($t = strtotime($time, 0)) {
            $pac['autoscan_timeout'] = $t;
            $pac['autoscan'] = 1;
        } else {
            $this->send($this->input['from'], "$time - wrong format", $this->input['message_id']);
        }
        $this->setPacConf($pac);
        $this->ipMenu();
    }

    public function templateCopy($type)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('send the template name'),
            $this->input['message_id'],
            reply: $this->i18n('send the template name'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'copyTemplate',
            'args'           => [$type],
        ];
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
        if (empty($this->input['file_id'])) {
            $this->send($this->input['chat'], 'send the template as a file');
            return;
        }
        $r    = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        $json = json_decode(file_get_contents($this->file . $r['result']['file_path']), true);
        if (!is_array($json)) {
            $this->send($this->input['chat'], 'wrong format');
            return;
        }
        $pac = $this->getPacConf();
        $pac["{$type}templates"][$name] = $json;
        $this->setPacConf($pac);
        $this->templates($type);
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
        $pac = $this->getPacConf();
        switch ($name) {
            case 'origin':
                file_put_contents("/config/$type.json", json_encode(json_decode($json, true), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                break;

            default:
                $pac["{$type}templates"][$name] = json_decode($json, true);
                break;
        }
        $this->setPacConf($pac);
        return [
            'status' => true,
        ];
    }

    public function delTemplate($type, $name)
    {
        $pac = $this->getPacConf();
        unset($pac["{$type}templates"][base64_decode($name)]);
        $this->setPacConf($pac);
        $this->templates($type);
    }

    public function copyTemplate($name, $type)
    {
        if (!$this->validTemplateName($name = trim((string) $name))) {
            $this->send($this->input['chat'], 'name: up to 24 bytes, letters, digits, space . _ -, not "origin"');
            return $this->templates($type);
        }
        $pac  = $this->getPacConf();
        $pac["{$type}templates"][$name] = json_decode(file_get_contents("/config/$type.json"), true);
        $this->setPacConf($pac);
        $this->templates($type);
    }

    public function downloadOrigin($type)
    {
        $f = new \CURLFile("/config/$type.json", 'application/json', 'origin.json');
        $this->sendFile($this->input['chat'], $f);
    }

    public function downloadTemplate($type, $name)
    {
        $pac = $this->getPacConf();
        $f = new \CURLStringFile(json_encode($pac["{$type}templates"][base64_decode($name)], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), base64_decode($name) . '.json', 'application/json');
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
                'web_app' => ['url' => "https://$domain/pac$hash?t=te&ty=$type"],
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
                'text'          => $this->i18n($pac["default{$type}template"] && !empty($pac["{$type}templates"][base64_decode($pac["default{$type}template"])]) ? 'off' : 'on'),
                'callback_data' => "/defaultTemplate $type",
            ],
        ];
        foreach ($templates ?: [] as $k => $v) {
            $data[] = [
                [
                    'text'          => $k,
                    'web_app' => ['url' => "https://$domain/pac$hash?t=te&ty=$type&te=" . urlencode($k)],
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
                    'text'          => $this->i18n($pac["default{$type}template"] == base64_encode($k) ? 'on' : 'off'),
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

    public function mainOutbound()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('send name'),
            $this->input['message_id'],
            reply: $this->i18n('ph: send name'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setMainOutbound',
            'args'           => [],
        ];
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

    public function getBytes($bytes)
    {
        $t = [
            'B',
            'KB',
            'MB',
            'GB',
            'TB',
        ];
        foreach ($t as $k => $v) {
            if ($k == 0) {
                continue;
            }
            if ($bytes / (1024 ** $k) < 1) {
                return round($bytes / (1024 ** ($k - 1)), 2) . " {$t[$k - 1]}";
            }
        }
    }

    public function xray($page = 0)
    {
        $c      = $this->getXray();
        $p      = $this->getPacConf();
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray');
        if (!empty($c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0])) {
            $text[] = "fake domain: <code>{$c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]}</code>";
        }
        $text[] = 'transport: ' . ($p['transport'] ?: 'Websocket');
        $st = $this->getXrayStats();
        $td = $this->getBytes($st['global']['download'] + $st['session']['download']);
        $tu = $this->getBytes($st['global']['upload'] + $st['session']['upload']);
        $text[] = "↓$td  ↑$tu";
        $data[] = [
            [
                'text'          => $this->i18n('reset stats'),
                'callback_data' => '/resetXrStats',
            ],
            [
                'text'          => $this->i18n('reset monthly') . ": " . $this->i18n(!empty($this->getPacConf()['reset_monthly']) ? 'on' : 'off'),
                'callback_data' => '/switchMonthlyStats',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('main outbound name: ') . ($p['outbound'] ?? 'proxy'),
                'callback_data' => '/mainOutbound',
            ],
        ];
        $ip_count = $p['ip_count'] ?: 1;
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
                'text'          => $this->i18n('RLTY') . ' ' . ($p['transport'] == 'Reality' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport Reality",
            ],
            [
                'text'          => $this->i18n('WS') . ' ' . ($p['transport'] == 'Websocket' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport Websocket",
            ],
            [
                'text'          => $this->i18n('XHTTP') . ($p['transport'] == 'xhttp' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport xhttp",
            ],
        ];

        if ($p['transport'] == 'Reality') {
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
                    'callback_data' => "/userXr $k",
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


    public function warpPlus()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('prompt warp'),
            $this->input['message_id'],
            reply: $this->i18n('enter key'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addWarpPlus',
            'args'           => [],
        ];
    }

    /**
     * New WARP account, profile and keys (wgcf register / generate), with
     * the WARP+ license key if given. WARP is down for a few seconds.
     */
    public function addWarpPlus($key)
    {
        $c    = $this->getPacConf();
        $chat = $this->input['chat'];
        $log  = '';
        $key  = trim((string) $key);
        if ($key === '+') {
            // re-registration with the current key
            $key = (string) ($c['warp'] ?? '');
        } elseif ($key === '-') {
            $key = '';
        }
        // checked before anything is torn down: the key goes into a sed
        // expression, WARP+ keys are letters, digits and dashes
        if ($key !== '' && !preg_match('~^[A-Za-z0-9-]{1,64}$~D', $key)) {
            $this->send($chat, 'wrong license key');
            return $this->warp();
        }

        $step = function($label, $cmd, $container) use ($chat, &$log) {
            $log .= "$label...";
            $this->sendDraft($chat, 1, $log);
            $out = trim($this->ssh($cmd, $container));
            $log .= $out ? "\n" . htmlspecialchars($out) . "\n" : " ok\n";
            $this->sendDraft($chat, 1, $log);
            return empty($out); // true = success (no output = exit 0)
        };

        if (!$step('stopping warp', 'wg-quick down /etc/warp/wgcf-profile.conf 2>/dev/null || true', 'wp')) {
            $this->send($chat, $log);
            return;
        }

        // Удаляем старые профиль и аккаунт
        if (!$step('removing old profile', 'rm -f /etc/warp/wgcf-profile.conf /etc/warp/wgcf-account.toml', 'wp')) {
            $this->send($chat, $log);
            return;
        }

        // Регистрируем новый аккаунт
        if (!$step('[warp] Registering WARP account...', 'cd /etc/warp && wgcf register --accept-tos', 'wp')) {
            $this->send($chat, $log);
            return;
        }

        if (!empty($key)) {
            $c['warp'] = $key;
            // Заменяем ключ в wgcf-account.toml
            if (!$step('setting license key', "sed -i 's/^license_key.*/license_key = \"$key\"/' /etc/warp/wgcf-account.toml", 'wp')) {
                $this->send($chat, $log);
                return;
            }
            // Обновляем аккаунт с ключом
            if (!$step('applying license key', 'cd /etc/warp && wgcf update', 'wp')) {
                $this->send($chat, $log);
                return;
            }
        } else {
            unset($c['warp']);
        }
        $this->setPacConf($c);

        if (!$step('generating profile', 'cd /etc/warp && wgcf generate', 'wp')) {
            $this->send($chat, $log);
            return;
        }
        $this->ssh("sed -i '/^Address.*:/d' /etc/warp/wgcf-profile.conf", 'wp');
        $this->ssh("sed -i '/^AllowedIPs.*::/d' /etc/warp/wgcf-profile.conf", 'wp');
        // see start_wp.sh: resolvconf cannot work in the container
        $this->ssh("sed -i '/^DNS *=/d' /etc/warp/wgcf-profile.conf", 'wp');

        $started = $step('starting warp', 'out=$(wg-quick up /etc/warp/wgcf-profile.conf 2>&1); ec=$?; [ "$ec" -ne 0 ] && printf "%s" "$out" | grep -v "skip sysctl"; exit $ec', 'wp');

        if (!$started) {
            $this->send($chat, $log);
            return;
        }

        sleep(1);
        // sendMessageDraft closes only when sendMessage is called — send a dummy and delete it
        $r = $this->send($chat, '.');
        if (!empty($r['result']['message_id'])) {
            $this->delete($chat, $r['result']['message_id']);
        }

        $this->warp();
    }

    /**
     * The WARP check goes through the tunnel and takes seconds, so the cron
     * loop (service container) runs it once a minute and keeps the answer
     * in a file; the main menu only reads it.
     */
    public function checkWarpStatus($force = false)
    {
        if ($force || empty($this->time_warp_status) || time() - $this->time_warp_status > 60) {
            $this->time_warp_status = time();
            $f = '/logs/.warp_status';
            file_put_contents("$f.tmp", $this->warpStatus());
            rename("$f.tmp", $f);
        }
    }

    public function cachedWarpStatus()
    {
        // no answer for 3 minutes (cron stopped): treat as unknown/off
        $f = '/logs/.warp_status';
        if (is_file($f) && time() - filemtime($f) < 180) {
            return trim(file_get_contents($f)) ?: 'off';
        }
        return 'off';
    }

    public function warpStatus()
    {
        // through the WARP socks proxy, like Xray's warp outbound (the name is
        // resolved by microsocks); a request through WARP can take a few
        // seconds. 1.1.1.1 does not work here: HTTP redirects, HTTPS hangs
        $st = $this->ssh('curl -s -m 8 -x socks5h://wp:1080 https://cloudflare.com/cdn-cgi/trace', 'xr');
        preg_match('~warp=(\w+)~', $st, $m);
        return trim($m[1]) ?: 'off';
    }

    public function analyzeXray()
    {
        while (true) {
            if (!empty($this->getPacConf()['ip_limit'])) {
                $this->pool = [];
                $log = '/logs/xray';
                // Xray creates the log after its restart with the limit on
                if (!($r = @fopen($log, 'r'))) {
                    sleep(10);
                    continue;
                }
                fseek($r, 0, SEEK_END);
                while (true) {
                    $pac = $this->getPacConf();
                    if (empty($pac['ip_limit'])) {
                        break;
                    }
                    $currentPosition = ftell($r);
                    clearstatcache();
                    $fileSize = (int) @filesize($log);
                    if ($fileSize < $currentPosition) {
                        // the log was cleaned: read it from the start
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
                fclose($r);
            }
            sleep(10);
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
        if (empty(preg_match('~(?<date>.+)\sfrom\s(?<ip>\d+\.\d+\.\d+\.\d+)(?=.+email:\s(?<email>.+))~', $line, $m))) {
            return;
        }
        if (!empty($m['ip']) && !empty($m['email'])) {
            $ip = ip2long($m['ip']);
            if (!empty($this->pool[$m['email']]['ip']) && $this->pool[$m['email']]['ip'] != $ip) {
                $this->pool[$m['email']]['ips'][$ip] = time();
            }
            if (!empty($this->pool[$m['email']]['ips']) && count($this->pool[$m['email']]['ips']) > ($pac['ip_count'] ?: 1)) {
                $xr = $this->getXray();
                foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
                    if (empty($v['off']) && $v['email'] == $m['email']) {
                        require __DIR__ . '/config.php';
                        foreach ($c['admin'] as $admin) {
                            $this->send($admin, "vless: {$m['email']} limit ip " . count($this->pool[$m['email']]['ips']) . ' > ' . ($pac['ip_count'] ?: 1), button: [[
                                [
                                    'text'          => $this->i18n($c['off'] ? 'off' : 'on'),
                                    'callback_data' => "/switchXr $k",
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

    public function warp()
    {
        $p      = $this->getPacConf();
        $c      = file_get_contents('/etc/warp/wgcf-profile.conf');
        $a      = file_get_contents('/etc/warp/wgcf-account.toml');
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('warp');
        // command output and files go into an HTML message: escaped
        $text[] = "status: <pre>" . htmlspecialchars((string) $this->ssh('wgcf trace', 'wp')) . '</pre>';
        $text[] = "key: <code>" . htmlspecialchars((string) ($p['warp'] ?? '')) . "</code>";
        $text[] = "<pre>" . htmlspecialchars((string) $a) . "</pre>";
        $text[] = "<pre>" . htmlspecialchars((string) $c) . "</pre>";
        $data[] = [
            [
                'text'          => $this->i18n('warp+ / re-registration'),
                'callback_data' => "/warpPlus",
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

    public function choiceTemplate($arg)
    {
        $arg = explode('_', $arg);
        $c   = $this->getXray();
        if (!empty($arg[2])) {
            $c['inbounds'][0]['settings']['clients'][$arg[1]]["{$arg[0]}template"] = $arg[2];
        } else {
            unset($c['inbounds'][0]['settings']['clients'][$arg[1]]["{$arg[0]}template"]);
        }
        file_put_contents('/config/xray.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->userXr($arg[1]);
    }

    public function templateUser($type, $i)
    {
        $c         = $this->getXray();
        $pac       = $this->getPacConf();
        $text[]    = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . " -> {$c['inbounds'][0]['settings']['clients'][$i]['email']}\n";
        $templates = $pac["{$type}templates"];
        $data[]    = [
            [
                'text'          => $this->i18n('default'),
                'callback_data' => "/choiceTemplate {$type}_$i",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('origin'),
                'callback_data' => "/choiceTemplate {$type}_{$i}_" . base64_encode('origin'),
            ],
        ];
        foreach ($templates ?: [] as $k => $v) {
            $data[] = [
                [
                    'text'          => $k,
                    'callback_data' => "/choiceTemplate {$type}_{$i}_" . base64_encode($k),
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/userXr $i",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
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
        $domain = $this->getDomain($pac['transport'] != 'Reality');
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        $name   = rawurlencode((string) ($c['email'] ?? ''));
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('xray') . ' -> ' . htmlspecialchars((string) ($c['email'] ?? ''));
        if (file_exists(__DIR__ . '/subscription.php')) {
            $text[] = "<a href='$scheme://{$domain}/pac$hash/sub?id={$c['id']}'>subscription</a>";
        }
        // sing-box has no XHTTP transport: no sing-box links while XHTTP is on
        $sing = ($pac['transport'] ?? '') != 'xhttp';

        $si = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'si',
            's' => $c['id'],
        ]));
        $cl = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'cl',
            's' => $c['id'],
        ]));

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

        $st       = $this->getXrayStats();
        [$download, $upload] = array_map([$this, 'getBytes'], $this->userTraffic($st, $c));
        $data[]   = [
            [
                'text'          => $this->i18n('reset stats') . ": ↓$download  ↑$upload",
                'callback_data' => "/resetXrUser $i",
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
        $singtemplate  = $c['singtemplate'] ? base64_decode($c['singtemplate']) : $this->i18n('default') . '(' . ($pac['defaultsingtemplate'] && !empty($pac['singtemplates'][base64_decode($pac['defaultsingtemplate'])]) ? base64_decode($pac['defaultsingtemplate']) : $this->i18n('origin')) . ')';
        $clashtemplate = $c['clashtemplate'] ? base64_decode($c['clashtemplate']) : $this->i18n('default') . '(' . ($pac['defaultclashtemplate'] && !empty($pac['clashtemplates'][base64_decode($pac['defaultclashtemplate'])]) ? base64_decode($pac['defaultclashtemplate']) : $this->i18n('origin')) . ')';
        $data[]        = array_values(array_filter([
            $sing ? [
                'text'          => $this->i18n('singbox') . ": $singtemplate",
                'callback_data' => "/templateUser sing $i",
            ] : null,
            [
                'text'          => $this->i18n('mihomo') . ": $clashtemplate",
                'callback_data' => "/templateUser clash $i",
            ],
        ]));
        if ($sing) {
            $data[] = [
                [
                    'text'          => $this->i18n('qr singbox'),
                    'callback_data' => "/qrXray {$i}_2",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('rename'),
                'callback_data' => "/renameXrUser $i",
            ],
            [
                // the user's state, pressing it switches the user on/off
                'text'          => $this->i18n($c['off'] ? 'off' : 'on') . ' ' . $this->i18n($c['off'] ? 'state off' : 'state on'),
                'callback_data' => "/switchXr $i",
            ],
            [
                'text'          => $this->i18n('delete'),
                'callback_data' => "/delxr $i",
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

    public function getDomain($cdn = false)
    {
        $c = $this->getPacConf();
        if ($cdn && $c['linkdomain']) {
            return $c['linkdomain'];
        }
        return $c['domain'] ?: $this->ip;
    }

    public function sub()
    {
        $xr     = $this->getXray();
        $pac    = $this->getPacConf();
        $st     = $this->getXrayStats();
        $domain = $this->requestDomain($pac);
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();
        $flag   = true;
        $client = null;
        $id = is_string($_GET['id'] ?? null) ? $_GET['id'] : '';
        foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($id !== '' && hash_equals((string) $v['id'], $id)) {
                if (empty($v['off'])) {
                    $flag = false;
                }
                $uid    = $v['id'];
                $email  = $v['email'];
                $expire = $v['time'];
                $client = $v;
                break;
            }
        }
        if ($flag) {
            header('404', true, 404);
            exit;
        }
        $suburl   = "<a href='$scheme://{$domain}/pac$hash/sub?id={$uid}'>subscription</a>";
        [$download, $upload] = array_map([$this, 'getBytes'], $this->userTraffic($st, $client ?? []));
        $singbox  = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'si',
            's' => $uid,
        ]));
        $clash = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'cl',
            's' => $uid,
        ]));
        $vless   = $this->linkXray($k);
        $_GET['s'] = $uid;
        foreach ([
          'singbox' => 'si',
          'clash'   => 'cl'
        ] as $k     => $v) {
            $_GET['t'] = $v;
            $configs[$k] = $this->subscription(1);
        }
        require __DIR__ . '/subscription.php';
    }

    public function subscription($return = false)
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
        $pac    = $this->getPacConf();
        if ($type == 'sing' && ($pac['transport'] ?? '') == 'xhttp') {
            // sing-box has no XHTTP transport: an error, not a config it rejects
            header('Content-Type: text/plain', true, 404);
            echo 'sing-box does not support the XHTTP transport';
            exit;
        }
        $domain = $this->requestDomain($pac);
        $xr     = $this->getXray();
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        $flag = true;
        $client = null;
        $sid = is_string($_GET['s'] ?? null) ? $_GET['s'] : '';
        foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($sid !== '' && hash_equals((string) $v['id'], $sid)) {
                if (empty($v['off'])) {
                    $flag = false;
                }
                $template = base64_decode($v["{$type}template"]);
                $uid      = $v['id'];
                $email    = $v['email'];
                $client   = $v;
                break;
            }
        }
        if ($flag) {
            header('500', true, 500);
            exit;
        }

        if (!empty($_GET['r'])) {
            $si = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                'h' => $hash,
                't' => 'si',
                's' => $uid,
            ]));
            $cl = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                'h' => $hash,
                't' => 'cl',
                's' => $uid,
            ]));
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
                $c = json_decode(file_get_contents("/config/{$type}.json"), true);
                break;
            case !empty($template):
                $c = $pac["{$type}templates"][$template];
                break;

            default:
                $c = $pac["{$type}templates"][base64_decode($pac["default{$type}template"])];
                break;
        }

        $outbound = $pac['outbound'] ?: 'proxy';
        $c = json_decode($this->replaceTags(json_encode($c), [
            '~outbound~' => $outbound,
        ]), true);
        foreach ($c['outbounds'] ?? [] as $k => $v) {
            if ($v['tag'] == $outbound) {
                $index = $k;
                break;
            }
        }
        if (!isset($index)) {
            foreach ($c['proxies'] ?? [] as $k => $v) {
                if ($v['name'] == $outbound) {
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
                switch ($pac['transport']) {
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
                    case $pac['transport'] == 'Reality':
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
                    case $pac['transport'] == 'xhttp':
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
            '"~pac~"'        => json_encode(array_keys(array_filter($pac['includelist'] ?: []))),
            '"~block~"'      => json_encode(array_keys(array_filter($pac['blocklist'] ?: []))),
            '"~warp~"'       => json_encode(array_keys(array_filter($pac['warplist'] ?: []))),
            '~dns~'          => "https://$domain/dns-query$hash/$uid",
            '~dnspath~'      => "/dns-query$hash/$uid",
            '~uid~'          => $uid,
            '~domain~'       => $domain,
            '~directdomain~' => $pac['domain'],
            '~cdndomain~'    => $pac['linkdomain'],
            '~short_id~'     => $xr['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0],
            '~email~'        => $email,
            '~public_key~'   => $pac['xray'],
            '~server_name~'  => $xr['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0],
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
        if (!empty($return)) {
            if ($_GET['t'] == 'cl') {
                return yaml_emit($c);
            }
            return json_encode($c);
        }

        if ($_GET['t'] == 'cl') {
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
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('prompt happ routing'),
            $this->input['message_id'],
            reply: 'happ://routing/onadd/...',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setHappRouting',
            'args'           => [],
        ];
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
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();
        foreach ($c['rules'] as $v) {
            if (array_key_exists('list', $v)) {
                if ($v['type'] == 'RULE-SET') {
                    if (!empty($_GET['r']) && $v['name'] == $_GET['r']) {
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
                        'url'      => "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                            'h' => $hash,
                            't' => 'cl',
                            's' => $uid,
                            'r' => $v['name'],
                        ])),
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
            if ($k[0] !== '"') {
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
                        if (preg_match('~\.srs$~', $url) && !empty($route['rules'][$t[$type]])) {
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
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        foreach ($route['rules'] as $k => $v) {
            if (!empty($v['createruleset'])) {
                foreach ($v['createruleset'] as $r) {
                    if (!empty($_GET['r']) && $r['name'] == $_GET['r']) {
                        $this->createSrs($r['name'], $r['rules']);
                    }
                    $ruleset[] = [
                        "tag"             => $r['name'],
                        "url"             => "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                            'h' => $hash,
                            't' => 'si',
                            's' => $uid,
                            'r' => $r['name'],
                        ])),
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
        $route['rule_set'] = array_merge($route['rule_set'] ?: [], $ruleset ?: []);
        if (empty($route['rule_set'])) {
            unset($route['rule_set']);
        }
        return $route;
    }

    public function getXray()
    {
        return json_decode(file_get_contents('/config/xray.json'), true);
    }

    public function setUpstreamDomain($domain)
    {
        // written into the nginx stream config: host names only
        if (!$this->validHost($domain)) {
            return;
        }
        $nginx = file_get_contents('/config/upstream.conf');
        $t = preg_replace('~#domain.+#domain~s', "#domain\n$domain reality;\n#domain", $nginx);
        file_put_contents('/config/upstream.conf', $t);
        $this->ssh("nginx -s reload 2>&1", 'up');
    }

    public function setUpstreamDomainOcserv($domain)
    {
        if ($domain && !$this->validHost($domain)) {
            return;
        }
        $sub   = $this->getHashSubdomain('oc');
        $nginx = file_get_contents('/config/upstream.conf');
        $t     = preg_replace('~#ocserv.+#ocserv~s', $domain ? "#ocserv\n" . ($sub ? '' : '#' ) . "$sub.$domain ocserv;\n#ocserv" : "#ocserv\n#$sub.\$domain ocserv;\n#ocserv", $nginx);
        file_put_contents('/config/upstream.conf', $t);
        $this->ssh("nginx -s reload 2>&1", 'up');
    }

    /**
     * Cookie value that opens the AdGuard panel. Separate from the path hash,
     * which every subscriber sees in their links.
     */
    public function getAdguardCookie(): string
    {
        return hash_hmac('sha256', 'adguard-cookie', $this->key);
    }

    public function getHashBot($notset = false)
    {
        $p = $this->getPacConf();
        if (!empty($p['hashbot'])) {
            return $p['hashbot'];
        }
        // secret path part for /pac, /webapp, /adguard, /ws: 128 bits, derived
        // from the bot token, stored on first use
        $p['hashbot'] = substr(hash_hmac('sha256', 'path', $this->key), 0, 32);
        if (empty($notset)) {
            $this->setPacConf($p);
        }
        return $p['hashbot'];
    }

    /**
     * A user name shown in menus and written into Xray/AdGuard configs and
     * client links: letters, digits, emoji (flags, skin tones, ZWJ
     * sequences), space and . _ @ -, up to 64 characters. No control or
     * other invisible characters.
     */
    public function validName($name): bool
    {
        return is_string($name) && (bool) preg_match('~^[\p{L}\p{N}\p{So}][\p{L}\p{N}\p{M}\p{So}\p{Sk} ._@\x{200D}-]{0,63}$~uD', $name);
    }

    /**
     * A password given to chpasswd/ocpasswd through a pipe: printable, one
     * line, no ':' (chpasswd field separator), 1-128 chars.
     */
    public function validSecret($secret): bool
    {
        return is_string($secret) && (bool) preg_match('~^[^\x00-\x1f\x7f:]{1,128}$~uD', $secret);
    }

    /**
     * A plain DNS host name (ASCII/punycode). Everything that ends up in
     * nginx, Xray or certbot configs as a domain must pass this.
     */
    public function validHost($host): bool
    {
        return is_string($host)
            && strlen($host) <= 253
            && (bool) preg_match('~^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)*\.?$~D', $host);
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
        return $this->getDomain($pac['transport'] != 'Reality');
    }

    public function cloakNginx()
    {
        $conf     = $this->getPacConf();
        if (!empty($conf['domain']) && !$this->validHost($conf['domain'])) {
            $conf['domain'] = '';
        }
        $template = file_get_contents('/config/nginx_default.conf');
        // $template = preg_replace('~server_name ip~', "server_name {$this->ip}", $template);
        $template = preg_replace('~server_name domain~', "server_name " . ($conf['domain'] ? " *.{$conf['domain']} {$conf['domain']}" : '_'), $template);
        if ($conf['domain'] && $conf['letsencrypt']) {
            $template = preg_replace('/#~([^\n]+)?/', "#~{$conf['letsencrypt']}", $template);
            preg_match_all('~#-domain.+?#-domain~s', $template, $m);
            foreach ($m[0] as $v) {
                $template = preg_replace('~#-domain.+?#-domain~s', $this->uncomment($v, 'domain'), $template, 1);
            }
        }
        $h  = $this->getHashBot();
        $ac = $this->getAdguardCookie();
        $s  = empty($conf['adgbrowser']) ? '' : '#';
        $r = <<<CONF
        location /adguard/ {
                access_log /logs/nginx_adguard_access;
                if (\$cookie_c != "$ac") {
                    $s rewrite .* /webapp redirect;
                }
                proxy_pass http://ad/;
                proxy_redirect / /adguard/;
                proxy_cookie_path / /adguard/;
            }
            location
        CONF;
        $template = preg_replace('~(location /adguard.+?})\s*location~s', $r, $template);
        $template = preg_replace('~(/webapp|/pac|/adguard|/ws|location /dns-query)~', '${1}' . $h, $template);
        file_put_contents('/config/nginx.conf', $template);
        $x = $this->getXray();
        if (!empty($x['inbounds'][0]['streamSettings']['wsSettings']['path'])) {
            $x['inbounds'][0]['streamSettings']['wsSettings']['path'] = "/ws$h";
            $this->restartXray($x);
        }
        if (!empty($x['inbounds'][0]['streamSettings']['xhttpSettings']['path'])) {
            $x['inbounds'][0]['streamSettings']['xhttpSettings']['path'] = "/ws$h";
            $this->restartXray($x);
        }

        return $this->ssh('nginx -s reload', 'ng');
    }

    public function getHashSubdomain($subdomain)
    {
        $p = $this->getPacConf();
        if (isset($p["{$subdomain}_domain"])) {
            return $p["{$subdomain}_domain"];
        }
        $p["{$subdomain}_domain"] = substr(hash('sha256', "$subdomain{$this->key}"), 0, 8);
        $this->setPacConf($p);
        return $p["{$subdomain}_domain"];
    }

    public function adguardChBr()
    {
        $c = $this->getPacConf();
        $c['adgbrowser'] = $c['adgbrowser'] ? 0 : 1;
        $this->setPacConf($c);
        $this->cloakNginx();
        $this->answer($this->input['callback_id'], $this->i18n($c['adgbrowser'] ? 'browser_notify_on' : 'browser_notify_off'), true);
        $this->menu('adguard');
    }

    public function adguardMenu()
    {
        $conf   = $this->getPacConf();
        $ip     = $this->ip;
        $domain = $this->getDomain();
        $hash   = $this->getHashBot();
        $scheme = empty($ssl = $this->nginxGetTypeCert()) ? 'http' : 'https';
        $text   = "$scheme://$domain/adguard$hash\nLogin: admin\nPass: <span class='tg-spoiler'>" . htmlspecialchars((string) ($conf['adpswd'] ?? '')) . "</span>\n\n";
        if ($ssl) {
            $text .= "DNS over HTTPS:\n<code>$ip</code>\n<code>$scheme://$domain/dns-query$hash" . (!empty($conf['adguardkey']) ? "/{$conf['adguardkey']}" : '') . "</code>\n\n";
            $text .= "DNS over TLS:\n<code>tls://" . (!empty($conf['adguardkey'] )? "{$conf['adguardkey']}." : '') . "$domain</code>";
        }
        $status = $this->i18n($this->adguardUp() ? 'on' : 'off');
        $safesearch = yaml_parse_file($this->adguard)['filtering']['safe_search']['enabled'];
        $text .= "\n\nstatus: $status\t\tsafesearch: " . $this->i18n($safesearch ? 'on' : 'off');
        $allowedClients = yaml_parse_file($this->adguard)['dns']['allowed_clients'];
        $text .= $allowedClients ? "\n\nallowed clients: \n - " . htmlspecialchars(implode("\n - ", $allowedClients)) : '';

        $data = [
            [
                [
                    'text'          => $this->i18n('web panel'),
                    'web_app' => [
                        "url" => "https://$domain/adguard$hash"
                    ],
                ],
                [
                    'text'          => $this->i18n('third party browser') . ': ' . $this->i18n(!empty($conf['adgbrowser']) ? 'on' : 'off'),
                    'callback_data' => '/adguardChBr'
                ],
            ],
            [
                [
                    'text'          => $this->i18n('change password'),
                    'callback_data' => "/adguardpsswd",
                ],
                [
                    'text'          => 'ClientID' . ($conf['adguardkey'] ? ": {$conf['adguardkey']}" : ''),
                    'callback_data' => "/setAdguardKey",
                ],
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('fill allowed clients'),
                'callback_data' => "/adgFillAllowedClients 0",
            ],
            [
                'text'          => $this->i18n('delete allowed clients'),
                'callback_data' => "/adgFillAllowedClients 1",
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
        $upstreams = yaml_parse_file($this->adguard)['dns']['upstream_dns'];
        if (!empty($upstreams)) {
            foreach ($upstreams as $k => $v) {
                $data[] = [
                    [
                        'text'          => $v,
                        'callback_data' => "/menu adguard",
                    ],
                    [
                        'text'          => $this->i18n('delete'),
                        'callback_data' => "/delupstream $k",
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

    public function adgFillAllowedClients($delete = false)
    {
        $pac = $this->getPacConf();
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $this->stopAd();
        $c = yaml_parse_file($this->adguard);
        if (!empty($delete)) {
            unset($c['dns']['allowed_clients']);
        } else {
            $c['dns']['allowed_clients'] = [];
            $c['dns']['allowed_clients'][] = '10.10.0.0/24';
            if (!empty($pac['adguardkey'])) {
                $c['dns']['allowed_clients'][] = $pac['adguardkey'];
            }
            $c['dns']['allowed_clients'][] = '10.0.2.0/24'; // openconnect
            if (!empty($xr = $this->getXray())) {
                foreach ($xr['inbounds'][0]['settings']['clients'] as $v) {
                    $c['dns']['allowed_clients'][] = $v['id'];
                }
            }
        }
        yaml_emit_file($this->adguard, $c);
        $this->startAd();
        $this->menu('adguard');
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

    public function expireCert()
    {
        $c = openssl_x509_read(file_get_contents("/certs/cert_public"));
        return openssl_x509_parse($c)["validTo_time_t"] ?: false;
    }

    public function domainsCert()
    {
        $domains = openssl_x509_parse(openssl_x509_read(file_get_contents("/certs/cert_public")))['extensions']["subjectAltName"];
        if (empty($domains)) {
            return false;
        }
        return array_map(fn($e) => trim($e), explode(',', str_replace('DNS:', '', $domains)));
    }

    public function updatebot()
    {
        $b = exec('git -C / rev-parse --abbrev-ref HEAD');
        $track  = trim(file_get_contents('/update/branch'));
        $data = [
            [
                [
                    'text'          => "$b => $track",
                    'callback_data' => "/branches",
                ],
                [
                    'text'          => $this->i18n('changelog'),
                    'callback_data' => "/changelog",
                ],
            ],
            [
                [
                    'text'          => $this->i18n('update bot'),
                    'callback_data' => "/applyupdatebot",
                ],
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        exec("git -C / branch -vv", $mm);
        return [
            'text' => '<pre><code class="language-shell">' . htmlentities(implode("\n", $mm)) . '</code></pre>',
            'data' => $data,
        ];
    }

    public function applyupdatebot()
    {
        // the latest traffic into the backup: Xray stops for the update
        $this->xrayStatsUser(true);
        $this->sendBackup($this->update);
        $r = $this->sendDraft($this->input['from'], 1, 'update...');
        file_put_contents('/update/reload_message', "{$this->input['from']}:{$r['result']['message_id']}");
        file_put_contents('/update/key', $this->key);
        file_put_contents('/update/curl', json_encode([
            'chat_id'    => $this->input['chat'],
            'message_id' => $r['result']['message_id'],
            'text'       => '~t~'
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        file_put_contents('/update/pipe', '1');
        $this->delete($this->input['from'], $this->input['message_id']);
    }

    public function restart()
    {
        $this->xrayStatsUser(true);
        $this->hostCommand('2', 'restart...');
    }

    public function rebuildMenu()
    {
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $this->i18n('Menu') . ' -> ' . $this->i18n('config') . ' -> ' . $this->i18n('rebuild images') . "\n\n"
            . "Every image is built anew, one at a time: fresh base images (Alpine, AdGuard Home) and package updates (PHP, OpenSSL, certificates). "
            . "All containers are stopped first: the bot and the VPN are off until the build ends, several minutes or more. "
            . "Settings and data are kept; a backup is sent first. The new images need free disk space.",
            [
                [['text' => $this->i18n('rebuild images'), 'callback_data' => '/rebuildYes']],
                [['text' => $this->i18n('back'), 'callback_data' => '/menu config']],
            ],
        );
    }

    public function rebuild()
    {
        $this->xrayStatsUser(true);
        $this->sendBackup();
        $this->hostCommand('3', 'rebuild images...');
    }

    // hands a command to scripts/update.sh on the host: 2 restart, 3 rebuild images
    public function hostCommand($cmd, $draft)
    {
        $r = $this->sendDraft($this->input['from'], 1, $draft);
        file_put_contents('/update/reload_message', "{$this->input['from']}:{$r['result']['message_id']}");
        file_put_contents('/update/key', $this->key);
        file_put_contents('/update/curl', json_encode([
            'chat_id'    => $this->input['chat'],
            'message_id' => $r['result']['message_id'],
            'text'       => '~t~'
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        file_put_contents('/update/pipe', $cmd);
        $this->delete($this->input['from'], $this->input['message_id']);
    }

    public function configMenu()
    {
        $conf = $this->getPacConf();
        $oc   = $this->getHashSubdomain('oc');
        if (!empty($conf['domain'])) {
            $ssl_expiry = $this->expireCert();
            $certs      = $this->domainsCert() ?: [];

            $text[] = "<blockquote>";
            $text[] = "Domains:";
            $text[] = $conf['domain'] . (in_array($conf['domain'], $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
            $text[] = 'openconnect ' . "$oc.{$conf['domain']}" . (in_array("$oc.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
            if (!empty($conf['adguardkey'])) {
                $text[] = "{$conf['adguardkey']}.{$conf['domain']}" . (in_array("{$conf['adguardkey']}.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '') . ' adguard DOT';
            }
            $text[] = "</blockquote>";
        } else {
            $text[] = $this->i18n('domain explain');
        }

        $data = [
            [
                [
                    'text'          => $conf['domain'] ? "{$this->i18n('delete')} {$conf['domain']}" : $this->i18n('install domain'),
                    'callback_data' => $conf['domain'] ? '/deldomain' : '/domain',
                ],
                [
                    'text'          => $this->i18n('nip.io'),
                    'callback_data' => '/addNipdomain',
                ],
            ],
        ];
        if ($conf['domain']) {
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
                'text'          => "{$this->i18n('page')}: " . ($conf['limitpage'] ?: 5),
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
                'text'          => '🔐 ' . $this->i18n(!empty($conf['backup_password']) ? 'on' : 'off'),
                'callback_data' => "/backupPassword",
            ],
        ];
        $backup = array_filter(explode('/', (string) ($conf['backup'] ?? '')));
        if (!empty($backup)) {
            if (!empty(strtotime($backup[0])) && !empty(strtotime($backup[1]))) {
                $backup = "{$backup[0]} start / {$backup[1]} period";
            } else {
                $backup = $this->i18n('off') . " {$conf['backup']} - wrong format";
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('backup') . ': ' . ($backup ?: $this->i18n('off')),
                'callback_data' => "/backup",
            ],
            [
                'text'          => $this->i18n('auto update') . ': ' .  $this->i18n($conf['autoupdate'] ? 'on' : 'off'),
                'callback_data' => "/autoupdate",
            ],
        ];
        // cover page at the site root ("fake html")
        $fake   = is_file('/app/webapp/override.html');
        $data[] = array_values(array_filter([
            [
                'text'          => $this->i18n('fake html') . ': ' . $this->i18n($fake ? 'on' : 'off'),
                'callback_data' => '/addOverrideHtml',
            ],
            $fake ? [
                'text'          => $this->i18n('delete') . ' ' . $this->i18n('fake html'),
                'callback_data' => '/delOverrideHtml',
            ] : null,
        ]));
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
                'text'          => $this->i18n('rebuild images'),
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
                'text'          => $this->i18n($c['ad'] ? 'on' : 'off') . ' 853 AdguardHome DoT',
                'callback_data' => "/hidePort ad",
            ]],
            [[
                'text'          => $this->i18n($c['dnstt'] ? 'on' : 'off') . ' 53 dnstt',
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

    public function branches()
    {
        exec('git -C / branch -r', $m);
        array_shift($m);
        foreach ($m as $k => $v) {
            $data[] = [
                [
                    'text'          => $v,
                    'callback_data' => "/changeBranch $k",
                ]
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu update",
            ]
        ];
        $this->update($this->input['from'], $this->input['message_id'], $this->i18n('manage updates'), $data);
    }

    public function changeBranch($i)
    {
        exec('git -C / branch -r', $m);
        array_shift($m);
        foreach ($m as $k => $v) {
            if ($i == $k) {
                file_put_contents('/update/branch', trim(str_replace('origin/', '', $v)));
            }
        }
        $this->menu('update');
    }

    public function logs()
    {
        $p = $this->getPacConf();
        foreach (scandir('/logs/') as $k => $v) {
            if (!preg_match('~^\.~', $v)) {
                $size   = filesize("/logs/$v");
                $data[] = [
                    [
                        'text'          => "$size $v",
                        'callback_data' => "/getLog $k",
                    ],
                    [
                        'text'          => $this->i18n('clean'),
                        'callback_data' => "/clearLog $k",
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('clean all'),
                'callback_data' => "/cleanLog",
            ],
        ];
        $autocleanlogs = array_filter(explode('/', (string) ($p['autocleanlogs'] ?? '')));
        if (!empty($autocleanlogs)) {
            if (!empty(strtotime($autocleanlogs[0])) && !empty(strtotime($autocleanlogs[1]))) {
                $autocleanlogs = "{$autocleanlogs[0]} start / {$autocleanlogs[1]} period";
            } else {
                $autocleanlogs = $this->i18n('off') . " {$p['autocleanlogs']} - wrong format";
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('autoclean'). ': ' . ($autocleanlogs ?: $this->i18n('off')),
                'callback_data' => "/autoCleanLogs",
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
            implode("\n", ['...']),
            $data ?: false,
        );
    }

    public function getLog($i)
    {
        foreach (scandir('/logs/') as $k => $v) {
            if (!preg_match('~^\.~', $v)) {
                $logs[$k] = $v;
            }
        }
        $this->sendFile(
            $this->input['chat'],
            curl_file_create("/logs/{$logs[$i]}"),
        );
    }

    public function clearLog($i)
    {
        foreach (scandir('/logs/') as $k => $v) {
            if ($i == $k) {
                file_put_contents("/logs/$v", '');
                break;
            }
        }
        $this->logs();
    }

    public function cleanLog()
    {
        foreach (scandir('/logs/') as $k => $v) {
            // the listed logs only: not . / .. or service files like .warp_status
            if (!preg_match('~^\.~', $v) && is_file("/logs/$v")) {
                file_put_contents("/logs/$v", '');
            }
        }
        $this->logs();
    }

    /**
     * After an update (scripts/update.sh resets the repository, so the
     * config files are back to their defaults) the settings come back from
     * the plain backup the bot left in /update/json. The update files are
     * cleared first, so a failure here cannot repeat on every start. A
     * backup is applied only over default settings: if the settings were
     * changed since (the backup is stale), they are kept and the backup is
     * set aside.
     */
    public function selfUpdate()
    {
        $rm = explode(':', trim((string) @file_get_contents('/update/reload_message')));
        $m  = trim((string) @file_get_contents('/update/message'));
        file_put_contents('/update/message', '');
        file_put_contents('/update/reload_message', '');
        require __DIR__ . '/config.php';
        $chat = preg_match('~^-?\d+$~D', $rm[0] ?? '') ? (int) $rm[0] : (int) ($c['admin'][0] ?? 0);
        $to   = preg_match('~^\d+$~D', $rm[1] ?? '') ? (int) $rm[1] : null;
        if (file_exists($this->update)) {
            $this->selfupdate = true;
            if ($m !== '') {
                $this->send($chat, '<pre>' . htmlspecialchars($m) . '</pre>', $to);
            }
            if ($this->defaultSettings()) {
                $r = $this->send($chat, "import settings");
                $this->input['chat']        = $chat;
                $this->input['message_id']  = $r['result']['message_id'] ?? 0;
                $this->input['callback_id'] = false;
                try {
                    $this->importFile($this->update);
                    @unlink($this->update);
                } catch (Throwable $e) {
                    $kept = '/update/json.failed-' . date('Ymd-His');
                    @rename($this->update, $kept);
                    $this->send($chat, 'import settings failed: ' . htmlspecialchars($e->getMessage()) . "\nthe backup is kept as " . basename($kept) . ' in the bot folder update/');
                }
            } else {
                $kept = '/update/json.unapplied-' . date('Ymd-His', (int) filemtime($this->update));
                @rename($this->update, $kept);
                $this->send($chat, 'a settings backup from ' . date('Y-m-d H:i', (int) filemtime($kept)) . ' was not applied: the current settings are not the defaults, so they were kept. The backup is saved as ' . basename($kept) . ' in the bot folder update/');
            }
        }
        $pac = $this->getPacConf();
        unset($pac['restart']);
        $this->setPacConf($pac);
    }

    // settings as after a repository reset: Xray config of the repository, no own settings in pac.json
    public function defaultSettings(): bool
    {
        $repo = shell_exec('git -C / show HEAD:config/xray.json 2>/dev/null');
        if (!empty($repo) && json_decode($repo, true) == $this->getXray()) {
            return true;
        }
        return !array_diff_key($this->getPacConf() ?: [], array_flip(['hashbot', 'oc_domain', 'restart']));
    }

    public function backup()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter like: start / period'),
            $this->input['message_id'],
            reply: $this->i18n('enter like: now / 12 hours'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setBackup',
            'args'           => [],
        ];
    }

    public function autoCleanLogs()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter like: start / period'),
            $this->input['message_id'],
            reply: $this->i18n('enter like: now / 12 hours'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setAutoCleanLogs',
            'args'           => [],
        ];
    }

    public function changeFakeDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter domain'),
            $this->input['message_id'],
            reply: $this->i18n('enter domain'),
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setFakeDomain',
            'args'           => [],
        ];
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

        $p['reality']['domain']      = $p['reality']['domain'] ?: 'yandex.ru';
        $p['reality']['destination'] = $p['reality']['destination'] ?: $p['reality']['domain'] . ':443';
        $p['transport'] = $transport;

        $p['reality']['domain']      = $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0] ?? $p['reality']['domain'];
        $p['reality']['destination'] = $x['inbounds'][0]['streamSettings']['realitySettings']['dest'] ?? $p['reality']['destination'];
        $p['reality']['shortId']     = $x['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0] ?? $p['reality']['shortId'];

        if (empty($p['xray'])) {
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
            $p['reality']['privateKey'] = $private;
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
                        "dest"         => $p['reality']['destination'] ?: $x['inbounds'][0]['streamSettings']['realitySettings']['dest'],
                        "maxClientVer" => "",
                        "maxTimeDiff"  => 0,
                        "minClientVer" => "",
                        "privateKey"   => $p['reality']['privateKey'],
                        "serverNames"  => [
                            $p['reality']['domain'] ?: $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]
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
            ? ($p['reality']['domain'] ?: $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0])
            : 't'
        );
        $this->setPacConf($p);
        $this->restartXray($x);
        $this->xray();
    }

    public function setBackup($text)
    {
        $text = trim($text);
        $c    = $this->getPacConf();
        if (empty($text)) {
            $c['backup'] = '';
        } else {
            [$start, $period] = explode('/', $text);
            if (!empty(strtotime($start)) && !empty(strtotime($period))) {
                $c['backup'] = implode(' / ', [date('Y-m-d H:i', strtotime($start)), trim($period)]);
            } else {
                $this->send($this->input['from'], $this->input['message'] . ' - wrong format');
            }
        }
        $this->setPacConf($c);
        $this->menu('config');
    }

    public function setAutoCleanLogs($text)
    {
        $text = trim($text);
        $c    = $this->getPacConf();
        if (empty($text)) {
            $c['autocleanlogs'] = '';
        } else {
            [$start, $period] = explode('/', $text);
            if (!empty(strtotime($start)) && !empty(strtotime($period))) {
                $c['autocleanlogs'] = implode(' / ', [date('Y-m-d H:i', strtotime($start)), trim($period)]);
            } else {
                $this->send($this->input['from'], $this->input['message'] . ' - wrong format');
            }
        }
        $this->setPacConf($c);
        $this->logs();
    }

    public function debug()
    {
        $file = __DIR__ . '/config.php';
        require $file;
        $c['debug'] = !$c['debug'];
        file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        $this->menu('config');
    }

    public function nginxGetTypeCert()
    {
        $conf = $this->ssh('cat /etc/nginx/nginx.conf', 'ng');
        preg_match("/#~([^\s]+)/", $conf, $m);
        return $m[1];
    }

    public function autoupdate()
    {
        $p = $this->getPacConf();
        $p['autoupdate'] = !$p['autoupdate'];
        $this->setPacConf($p);
        $this->menu('config');
    }

    public function ssh($cmd, $service, $wait = true, $log = '/dev/null')
    {
        $data = '';
        try {
            $c = ssh2_connect($service, 22, ['hostkey' => 'ssh-ed25519']);
            if (empty($c)) {
                throw new Exception("no connection to $service: \n$cmd\n" . var_export($c, true));
            }
            // the container must show its own host key (made by php, ./sshhost)
            $pub = preg_match('~^[a-z]+$~', $service) ? @file_get_contents("/ssh/host_$service.pub") : false;
            $blob = base64_decode(explode(' ', trim((string) $pub))[1] ?? '', true);
            if (!$blob || strcasecmp(ssh2_fingerprint($c, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_HEX), sha1($blob)) !== 0) {
                error_log("ssh $service: host key mismatch, command not sent");
                throw new Exception("host key mismatch: $service\n$cmd");
            }
            $a = ssh2_auth_pubkey_file($c, 'root', '/ssh/key.pub', '/ssh/key');
            if (empty($a)) {
                throw new Exception("auth fail: \n$cmd\n" . var_export($a, true));
            }

            // Оборачиваем команду для выполнения в фоновом режиме
            if (!$wait) {
                // nohup запускает процесс независимо от SSH-сессии
                // & переносит процесс в фон
                // </dev/null >/dev/null 2>&1 перенаправляет все потоки ввода-вывода
                $cmd = "nohup sh -c \"$cmd 2>&1 | tee -a $log >&3\" 3>/proc/1/fd/1 </dev/null &";
            }


            $s = ssh2_exec($c, $cmd);
            if (empty($s)) {
                throw new Exception("exec fail: \n$cmd\n" . var_export($s, true));
            }

            $data = "";
            if ($wait) {
                // Только для синхронных команд читаем вывод
                stream_set_blocking($s, true);
                while ($buf = fread($s, 4096)) {
                    $data .= $buf;
                }
            } else {
                // Для фоновых команд просто даем время запуститься
                stream_set_blocking($s, false);
                usleep(100000); // 100ms для запуска процесса
            }

            fclose($s);
            ssh2_disconnect($c);
        } catch (Exception | Error $e) {
            if (!empty($GLOBALS['debug'])) {
                $this->send($this->input['chat'], $e->getMessage(), $this->input['message_id']);
            }
        }
        return $data;
    }

    public function request($method, $data, $json_header = 0)
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $this->api . $method,
            CURLOPT_CUSTOMREQUEST  => 'POST',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_HTTPHEADER => $json_header ? [
                'Content-Type: application/json'
            ] : [],
            CURLOPT_POSTFIELDS     => $data,
        ]);
        $res = curl_exec($ch);
        $r   = json_decode($res, true);
        // log failed calls: no answer at all, or Telegram refused the request
        if (!is_array($r) || empty($r['ok'])) {
            // method and Telegram's answer only: the request itself may carry
            // links, keys or backups
            $why = $res === false ? 'curl: ' . curl_error($ch) : (is_array($r) ? ($r['error_code'] ?? '') . ' ' . ($r['description'] ?? '') : substr((string) $res, 0, 200));
            file_put_contents('/logs/requests_error', date('Y-m-d H:i:s ') . "$method: $why\n", FILE_APPEND);
        }
        return $r;
    }

    public function polling()
    {
        $offset = -1;
        while (true) {
            $r = $this->request('getUpdates', [
                'offset'          => $offset,
                'limit'           => 3,
                'timeout'         => 5,
                // explicit: without it Telegram keeps the list from an
                // earlier webhook or bot on this token, which may leave out
                // button presses (callback_query)
                'allowed_updates' => json_encode(['message', 'callback_query', 'inline_query', 'channel_post', 'my_chat_member']),
            ]);
            if (!empty($r['description'])) {
                error_log('getUpdates error: ' . $r['description']);
                sleep(3);
                continue;
            }
            file_put_contents('/start', 1);
            if (!empty($r['result'])) {
                foreach ($r['result'] as $v) {
                    try {
                        $this->input($v);
                    } catch (Throwable $e) {
                        error_log($e);
                    } finally {
                        session_write_close();
                    }
                    $offset = max($offset, $v['update_id']);
                }
                $offset++;
            } else {
                sleep(1);
            }
        }
    }

    public function setcommands()
    {
        $data = [
            'commands' => [
                [
                    'command'     => 'menu',
                    'description' => '...',
                ],
                [
                    'command'     => 'id',
                    'description' => 'your id telegram',
                ],
            ]
        ];
        $this->request('setMyCommands', json_encode($data), 1);
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        if (is_null($text)) {
            $text = '';
        }
        if ($button) {
            $extra = ['inline_keyboard' => $button];
        }
        if (false !== $reply) {
            $extra = [
                'force_reply'             => true,
                'input_field_placeholder' => $reply,
                'selective'               => true,
            ];
        }
        $length = 3096;
        if (mb_strlen($text, 'utf-8') > $length) {
            $tails = $this->splitText($text, $length);
            foreach ($tails as $k => $v) {
                $data = [
                    'chat_id'                  => $chat,
                    'text'                     => "$v\n",
                    'parse_mode'               => $mode,
                    // 'disable_web_page_preview' => true,
                    'disable_notification'     => $disable_notification,
                    'reply_to_message_id'      => 0 == $k && $to > 0 ? $to : false,
                ];
                if ($k == array_key_last($tails)) {
                    if ($extra) {
                        $data['reply_markup'] = json_encode($extra);
                    }
                }
                $r = $this->request('sendMessage', $data);
            }
        } else {
            $data = [
                'chat_id'                  => $chat,
                'text'                     => $text,
                'parse_mode'               => $mode,
                // 'disable_web_page_preview' => true,
                'disable_notification'     => $disable_notification,
                'reply_to_message_id'      => $to,
            ];
            if (!empty($extra)) {
                $data['reply_markup'] = json_encode($extra);
            }
            $r = $this->request('sendMessage', $data);
        }
        return $r;
    }

    public function splitText($text, $size = 4096)
    {
        $tails = preg_split('~\n~', $text);
        if (!empty($tails)) {
            foreach ($tails as $v) {
                $lines[] = [
                    'length' => mb_strlen($v, 'utf-8'),
                    'text'   => $v,
                ];
            }
            $i = 0;
            foreach ($lines as $v) {
                $i += $v['length'];
                $output[ceil($i / $size)] .= $v['text'] . "\n";
            }
            return array_values($output);
        } else {
            return [$text];
        }
    }

    public function sendDraft($chat, $draft_id, $text = '', $mode = 'HTML')
    {
        $data = [
            'chat_id'    => $chat,
            'draft_id'   => $draft_id,
            'text'       => $text,
            'parse_mode' => $mode,
        ];
        return $this->request('sendMessageDraft', json_encode($data), 1);
    }

    public function sendPhoto($chat, $id_url_cFile, $caption = false, $to = false)
    {
        return $this->request('sendPhoto', [
            'chat_id'             => $chat,
            'photo'               => $id_url_cFile,
            'caption'             => $caption,
            'reply_to_message_id' => $to,
            'parse_mode'          => 'html',
        ]);
    }

    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false)
    {
        return $this->request('sendDocument', [
            'chat_id'             => $chat,
            'document'            => $id_url_cFile,
            'caption'             => $caption,
            'reply_to_message_id' => $to,
            'parse_mode'          => 'html',
        ]);
    }

    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        if ($button) {
            $extra = ['inline_keyboard' => $button];
        }
        if ($reply !== false) {
            $extra = [
                'force_reply'             => true,
                'input_field_placeholder' => $reply
            ];
        }
        $data = [
            'chat_id'                  => $chat,
            'message_id'               => $message_id,
            'text'                     => $text,
            'parse_mode'               => $mode,
            'disable_web_page_preview' => true,
        ];
        if (!empty($extra)) {
            $data['reply_markup'] = json_encode($extra);
        }
        return $this->request('editMessageText', $data);
    }

    public function answer($callback_id, $textNotify = false, $notify = false)
    {
        return $this->request('answerCallbackQuery', [
            'callback_query_id' => $callback_id,
            'show_alert'        => $notify,
            'text'              => $textNotify,
        ]);
    }

    public function delete($chat, $message_id)
    {
        $data = [
            'chat_id'    => $chat,
            'message_id' => $message_id,
        ];
        return $this->request('deleteMessage', $data);
    }


}
