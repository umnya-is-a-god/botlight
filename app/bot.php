<?php

class Bot
{
    // nginx in ng and up runs with the config the bot writes into /data
    // (mounted as /etc/nginx/bot): every nginx call names it
    const NGINX_NG = 'nginx -c /etc/nginx/bot/nginx.conf';
    const NGINX_UP = 'nginx -c /etc/nginx/bot/upstream.conf';
    // Xray's config test: its messages (on stdout) only when it fails
    const XRAY_TEST = 'o=$(xray run -test -format json -config %s 2>&1); r=$?; [ $r -eq 0 ] || printf "%%s" "$o" | tail -n 20 >&2; [ $r -eq 0 ]';

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
    // true in the web pools (index.php): no bot token, read-only views
    public $web;
    // AdGuard's config was changed since it was last started
    public $adguardChanged = false;
    // messages to delete later: [chat, message id, time]
    public $later = [];
    public $time_warp_profile;
    public $time_logrotate;
    // when the IP limit last alerted about a user
    public $ipAlerted = [];
    // the last scan of the analysis menu (task.php logs analysis)
    public $analysisCache = '/tmp/analysis.json';
    public $time_oc_traffic;

    public function __construct($key, $i18n, $web = false)
    {
        $api = getenv('TELEGRAM_API') ?: 'api.telegram.org';
        $this->web      = $web;
        $this->key      = $key;
        $this->api      = "https://$api/bot$key/";
        $this->file     = "https://$api/file/bot$key/";
        $this->pac      = BOT_DATA . '/pac.json';
        $this->ip       = filter_var(getenv('IP'), FILTER_VALIDATE_IP) ?: '';
        $this->i18n     = $i18n;
        $this->language = ($this->getPacConf()['language'] ?? null) ?: 'en';
        $this->dns      = '1.1.1.1, 8.8.8.8';
        $this->mtu      = 1350;
        $this->limit    = ($this->getPacConf()['limitpage'] ?? null) ?: 5;
        $this->adguard  = BOT_DATA . '/adguard/AdGuardHome.yaml';
        // a plain settings backup that versions before ./data left for
        // their update (read once by selfUpdate, never written now)
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

    // config.php ($c: bot token, admins), see bot_config()
    public function config(): array
    {
        return bot_config();
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
        // private chats only: not groups, channels or other chat events
        $type = $input['message']['chat']['type'] ?? $input['callback_query']['message']['chat']['type'] ?? '';
        if ($type !== 'private') {
            return;
        }
        $this->auth();
        if ($this->admin) {
            $this->session();
            $this->action();
        }
        $this->callbackCheck();
    }

    public function auth()
    {
        try {
            $c = $this->config();
        } catch (Throwable $e) {
            // unreadable or damaged config.php: nobody is admin, and nobody
            // becomes the first admin over a config that is still there
            error_log("auth: $e");
            return;
        }
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
            bot_config_save($c);
            $this->writeWebSecrets();
        } elseif (!is_array($c['admin'])) {
            $c['admin'] = [$c['admin']];
            bot_config_save($c);
        }
        if ($from !== 0 && in_array($from, array_map('intval', $c['admin']), true)) {
            $this->admin = true;
        }
    }

    public function callbackCheck()
    {
        if (empty($this->callback) && !empty($this->input['callback_id'])) {
            $this->answer($this->input['callback_id'], $this->debugOn() ? $this->input['callback'] : false);
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
            case preg_match('~^/switchMonthlyStats( oc)?$~', $this->input['callback'], $m):
                $this->switchMonthlyStats(!empty($m[1]));
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
            case preg_match('~^/analysisIp(?:\s(\d+))?(\snew)?$~', $this->input['callback'], $m):
                $this->analysisIp((int) ($m[1] ?? 0), new: !empty($m[2]));
                break;
            case preg_match('~^/ipMenu$~', $this->input['callback'], $m):
                $this->ipMenu();
                break;
            case preg_match('~^/cleanDeny(?:\s(\d))?$~', $this->input['callback'], $m):
                $this->cleanDeny($m[1]);
                break;
            case preg_match('~^/denyList (.+?)(?:\s(\d))?$~', $this->input['callback'], $m):
                $this->denyList($m[1], ($m[2] ?? null) ?: 0);
                break;
            case preg_match('~^/cleanLogs (.+?)(?:\s(1))?$~', $this->input['callback'], $m):
                $this->cleanLogs($m[1], $m[2]);
                break;
            case preg_match('~^/allowIp (.+?) (\d+)(?:\s(\d+))?$~', $this->input['callback'], $m):
                $this->allowIp($m[1], $m[2], $m[3]);
                break;
            case preg_match('~^/ipInfo ([0-9A-Fa-f:.]{3,45})$~', $this->input['callback'], $m):
                $this->ipInfo($m[1]);
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
            case preg_match('~^/adgAllowed$~', $this->input['callback'], $m):
                $this->adgAllowed();
                break;
            case preg_match('~^/addLinkDomain$~', $this->input['callback'], $m):
                $this->addLinkDomain();
                break;
            case preg_match('~^/id$~', $this->input['message'], $m):
                $this->send($this->input['chat'], "your id: {$this->input['from']}\nchat id: {$this->input['chat']}", $this->input['message_id']);
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
            case preg_match('~^/applyupdatebot( yes)?$~', $this->input['callback'], $m):
                $this->applyupdatebot(!empty($m[1]));
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
            case preg_match('~^/changeBranch ([0-9a-f]{8})( yes)?$~', $this->input['callback'], $m):
                $this->changeBranch($m[1], !empty($m[2]));
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
            // logs by file name (checked in logFile), not by position
            case preg_match('~^/getLog ([\w.-]{1,48})$~', $this->input['callback'], $m):
                $this->getLog($m[1]);
                break;
            case preg_match('~^/clearLog ([\w.-]{1,48})$~', $this->input['callback'], $m):
                $this->clearLog($m[1]);
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
            // Xray users by their id (stable across on/off), not by position
            case preg_match('~^/renameXrUser ([\w-]{1,40})$~', $this->input['callback'], $m):
                $this->withXr($m[1], fn($i) => $this->renameXrUser($m[1]));
                break;
            case preg_match('~^/resetXrUser ([\w-]{1,40})$~', $this->input['callback'], $m):
                $this->withXr($m[1], fn($i) => $this->resetXrUser($i));
                break;
            case preg_match('~^/newSubXr ([\w-]{1,40})( yes)?$~', $this->input['callback'], $m):
                $this->withXr($m[1], fn($i) => $this->newSubXr($i, !empty($m[2])));
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
            case preg_match('~^/addAdminYes (\d{1,20})$~', $this->input['callback'], $m):
                $this->addAdminYes((int) $m[1]);
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
            case preg_match('~^/setSSL (letsencrypt)( yes)?$~', $this->input['callback'], $m):
                $this->setSSL($m[1], !empty($m[2]));
                break;
            case preg_match('~^/lang (\w+)$~', $this->input['callback'], $m):
                $this->setLang($m[1]);
                break;
            case preg_match('~^/deletessl$~', $this->input['callback'], $m):
                $this->deleteSSL();
                break;
            // OpenConnect users by shortId() of the name
            case preg_match('~^/deloc ([0-9a-f]{10})$~', $this->input['callback'], $m):
                $this->deloc($m[1]);
                break;
            case preg_match('~^/ocUser ([0-9a-f]{10})$~', $this->input['callback'], $m):
                $this->ocUser($m[1]);
                break;
            case preg_match('~^/resetOcStats(?: ([0-9a-f]{10}))?$~', $this->input['callback'], $m):
                $this->resetOcStats($m[1] ?? null);
                break;
            case preg_match('~^/renameOcUser ([0-9a-f]{10})$~', $this->input['callback'], $m):
                $this->renameOcUser($m[1]);
                break;
            case preg_match('~^/userXr ([\w-]{1,40})$~', $this->input['callback'], $m):
                $this->withXr($m[1], fn($i) => $this->userXr($i));
                break;
            // /chT s|c <user id> d (default) | o (origin) | <template id>
            case preg_match('~^/chT ([sc]) ([\w-]{1,40}) (d|o|[0-9a-f]{10})$~', $this->input['callback'], $m):
                $this->withXr($m[2], fn($i) => $this->choiceTemplate(($m[1] ?? null) == 's' ? 'sing' : 'clash', $i, $m[3]));
                break;
            case preg_match('~^/templateUser (sing|clash) ([\w-]{1,40})$~', $this->input['callback'], $m):
                $this->withXr($m[2], fn($i) => $this->templateUser($m[1], $i));
                break;
            case preg_match('~^/switchXr ([\w-]{1,40})$~', $this->input['callback'], $m):
                $this->withXr($m[1], fn($i) => $this->switchXr($i));
                break;
            case preg_match('~^/delxr ([\w-]{1,40})$~', $this->input['callback'], $m):
                $this->withXr($m[1], fn($i) => $this->delxr($i));
                break;
            case preg_match('~^/listXr (\d+)$~', $this->input['callback'], $m):
                $this->listXr($m[1]);
                break;
            case preg_match('~^/deladmin (\d+)( yes)?$~', $this->input['callback'], $m):
                $this->delAdmin($m[1], !empty($m[2]));
                break;
            case preg_match('~^/adminCard (\d+)$~', $this->input['callback'], $m):
                $this->adminCard($m[1]);
                break;
            case preg_match('~^/renameAdmin (\d+)$~', $this->input['callback'], $m):
                $this->renameAdmin($m[1]);
                break;
            case preg_match('~^/qrXray ([\w-]{1,40})(?:_(\d+))?$~', $this->input['callback'], $m):
                $this->withXr($m[1], fn($i) => $this->qrXray($i, ($m[2] ?? '') ?: false));
                break;
            case preg_match('~^/delupstream ([0-9a-f]{10})$~', $this->input['callback'], $m):
                $this->delupstream($m[1]);
                break;
            case preg_match('~^/deldomain$~', $this->input['callback'], $m):
                $this->delDomain();
                break;
            case preg_match('~^/addNipdomain$~', $this->input['callback'], $m):
                $this->addNipdomain();
                break;
            case preg_match('~^/(?P<action>change|delete)(?P<typelist>includelist|blocklist|warplist|rulessetlist|white|deny) (?P<arg>[0-9a-f]{10})(?: (?P<page>\d+))?$~', $this->input['callback'], $m):
                $this->listPacChange($m['typelist'], $m['action'], $m['arg'], ($m['page'] ?? null) ?: 0);
                break;
            case preg_match('~^/domain$~', $this->input['callback'], $m):
                $this->domain();
                break;
            case preg_match('~^/warp$~', $this->input['callback'], $m):
                $this->warp();
                break;
            case preg_match('~^/secrets (adguard|ocserv|dnstt|warp)$~', $this->input['callback'], $m):
                $this->showSecrets($m[1]);
                break;
            case preg_match('~^/warpPlus$~', $this->input['callback'], $m):
                $this->warpPlus();
                break;
            case preg_match('~^/xray(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xray(($m[1] ?? null) ?: 0);
                break;
            case preg_match('~^/xtlsblock(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsblock(($m[1] ?? null) ?: 0);
                break;
            case preg_match('~^/routes(?: (\d+))?$~', $this->input['callback'], $m):
                $this->routes(($m[1] ?? null) ?: 0);
                break;
            case preg_match('~^/xtlswarp(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlswarp(($m[1] ?? null) ?: 0);
                break;
            case preg_match('~^/xtlsrulesset(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsrulesset(($m[1] ?? null) ?: 0);
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
            case preg_match('~^/import( yes)?$~', $this->input['callback'], $m):
                $this->import(!empty($m[1]));
                break;
            case preg_match('~^/importList (includelist|blocklist|warplist|rulessetlist|white|deny)$~', $this->input['callback'], $m):
                $this->importList($m[1]);
                break;
            case !empty($this->input['reply']):
                $this->reply();
                break;
        }
    }

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

    /**
     * Replaces a config file a container uses, but only once the program
     * there accepts the new content: written next to it as <file>.new,
     * tested in the container ($test: the command, %s: the .new file as the
     * container sees it), then renamed over the old one, which is kept as
     * <file>.prev (rollbackConfig). A rejected config is removed, the old
     * one stays and the admin gets the error. A container that cannot be
     * reached (not running yet) gets the file untested.
     */
    public function applyConfig(string $file, string $content, string $service, string $test, int $mode = 0600, ?int $gid = null): bool
    {
        $dir = [
            'xr' => '/xray',
            'ng' => '/etc/nginx/bot',
            'up' => '/etc/nginx/bot',
            'oc' => '/etc/ocserv',
            'ad' => '/config',
        ][$service];
        return bot_lock($file, function () use ($file, $content, $service, $test, $mode, $gid, $dir) {
            bot_write("$file.new", $content, $mode, $gid, false);
            $r = $this->sshRun(sprintf($test, escapeshellarg($dir . '/' . basename($file) . '.new')), $service);
            if ($r['rc'] !== null && $r['rc'] !== 0) {
                @unlink("$file.new");
                $this->configRejected(basename($file), trim($r['err'] . "\n" . $r['out']));
                return false;
            }
            if ($r['rc'] === null) {
                error_log("applyConfig $file: $service not reachable, written without a test");
            }
            if (is_file($file)) {
                bot_write("$file.prev", bot_read($file), $mode, $gid, false);
            }
            if (!rename("$file.new", $file)) {
                throw new RuntimeException("cannot write $file");
            }
            return true;
        });
    }

    // the config before the last applyConfig back in place
    public function rollbackConfig(string $file): bool
    {
        return bot_lock($file, fn() => is_file("$file.prev") && rename("$file.prev", $file));
    }

    // a config was not applied: the admin who changed it (or the main admin) is told why
    public function configRejected(string $what, string $error)
    {
        error_log("config $what rejected: $error");
        try {
            $chat = (int) ($this->input['chat'] ?? 0) ?: (int) ($this->config()['admin'][0] ?? 0);
        } catch (Throwable $e) {
            return;
        }
        if ($chat) {
            $this->send($chat, "$what: the change was not applied, the old config is kept\n<pre>" . htmlspecialchars(mb_substr($error, -3000)) . '</pre>');
        }
    }

    /**
     * Before the bot starts (scripts/start_php.sh): the other containers
     * wait for php to be healthy, so they start with these files in place
     * and in the current format. Nothing is reloaded here.
     */
    public function prepare()
    {
        $this->dataPermissions();
        $pac = $this->getPacConf();
        // the log cleaning schedule of earlier versions: logs rotate now
        if (array_key_exists('autocleanlogs', $pac) || array_key_exists('last_clean_logs_time', $pac) || array_key_exists('adgbrowser', $pac)) {
            // also the "third party browser" switch: the cookie is always checked
            unset($pac['autocleanlogs'], $pac['last_clean_logs_time'], $pac['adgbrowser']);
            $this->setPacConf($pac);
        }
        if (isset($pac['singtemplates']) || isset($pac['clashtemplates']) || array_intersect_key($pac, array_flip(['adpswd', 'ocserv', 'dnsttPassword', 'warp', 'backup_password'])) || isset($pac['reality']['privateKey'])) {
            // templates and secrets of earlier versions, kept in the settings
            $this->importPac($pac);
        }
        // the camouflage secret, for the Mini App (ocserv.conf is root only)
        if (preg_match('~^camouflage_secret\s*=\s*"([^"\n]*)"~m', (string) @file_get_contents(BOT_DATA . '/ocserv/ocserv.conf'), $m)) {
            $this->setSecret('oc_camouflage', $m[1]);
        }
        // once: ocserv's workers isolated (seccomp, resource limits), the
        // default of ocserv itself. Set back to false by hand, it stays so.
        $this->updateState(function ($st) {
            if (empty($st['oc_isolate_workers'])) {
                $f = BOT_DATA . '/ocserv/ocserv.conf';
                $c = bot_read($f);
                $n = preg_replace('~^isolate-workers\s*=\s*false[ \t]*$~m', 'isolate-workers = true', $c);
                if ($n !== $c) {
                    bot_write($f, $n);
                }
                $st['oc_isolate_workers'] = 1;
            }
            return $st;
        });
        $f = BOT_DATA . '/ocserv/ocserv.conf';
        $c = bot_read($f);
        if (($n = $this->ocservConf($c)) !== $c) {
            bot_write($f, $n);
        }
        $this->syncWarpProfile();
        $this->getHashBot();
        $this->getAdminHash();
        $this->getHashSubdomain('oc');
        if (!is_file(BOT_DATA . '/ng/limit_exempt.conf')) {
            bot_write(BOT_DATA . '/ng/limit_exempt.conf', $this->limitExemptConf());
        }
        $this->saveXrayView($this->getXray());
        $this->writeWebSecrets();
        bot_write(BOT_DATA . '/up/upstream.conf', $this->upstreamConf(bot_read(BOT_DATA . '/up/upstream.conf')));
        $this->cloakNginx(false);
        $this->writeWarpKey();
    }

    /**
     * Who may read what in /data (the web pools run as botweb/botadmin,
     * dockerfile/php.dockerfile). Everything else stays root only.
     */
    public function dataPermissions()
    {
        foreach (['/web' => 0750, '/templates' => 02770, '/secrets' => 0750] as $d => $mode) {
            if (!is_dir(BOT_DATA . $d)) {
                mkdir(BOT_DATA . $d, $mode);
            }
        }
        // root only (the containers that mount them run as root)
        foreach (['/xray', '/adguard', '/ocserv', '/octraffic', '/up', '/ng', '/dnstt', '/backup', '/letsencrypt'] as $d) {
            if (is_dir(BOT_DATA . $d)) {
                chmod(BOT_DATA . $d, 0700);
            }
        }
        foreach ([
            ''           => [0750, BOT_GID_WEB],
            '/web'       => [0750, BOT_GID_WEB],
            '/templates' => [02770, BOT_GID_WEB],
            '/secrets'   => [0750, BOT_GID_SECRET],
            '/pac.json'  => [0640, BOT_GID_WEB],
            '/www'       => [0755, null],
        ] as $f => [$mode, $gid]) {
            if (file_exists(BOT_DATA . $f)) {
                chmod(BOT_DATA . $f, $mode);
                if ($gid !== null) {
                    chgrp(BOT_DATA . $f, $gid);
                }
            }
        }
        foreach ([
            '/xray.stats'         => [0640, BOT_GID_WEB],
            '/www/override.html'  => [0644, null],
            '/config.php'         => [0600, 0],
            '/templates/sing.json'         => [0660, BOT_GID_WEB],
            '/templates/clash.json'        => [0660, BOT_GID_WEB],
            '/templates/sing.origin.json'  => [0660, BOT_GID_WEB],
            '/templates/clash.origin.json' => [0660, BOT_GID_WEB],
        ] as $f => [$mode, $gid]) {
            if (is_file(BOT_DATA . $f)) {
                chmod(BOT_DATA . $f, $mode);
                if ($gid !== null) {
                    chgrp(BOT_DATA . $f, $gid);
                }
            }
        }
    }

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

    /**
     * The WARP+ license key for scripts/start_wp.sh, in the warp volume
     * (shared by php and wp only): wp needs no access to the settings.
     */
    public function writeWarpKey()
    {
        $key = $this->secret('warp');
        if (is_dir('/etc/warp')) {
            bot_write('/etc/warp/license_key', preg_match('~^[A-Za-z0-9-]{1,64}$~D', $key) ? "$key\n" : '');
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

    // $uid: the user's id (renXrUs finds the user again by it)
    public function renameXrUser($uid)
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
            'args'           => [$uid],
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
            bot_write(BOT_DATA . '/www/override.html', $f, 0644);
        }
        $this->menu('config');
    }

    public function delOverrideHtml()
    {
        @unlink(BOT_DATA . '/www/override.html');
        $this->menu('config');
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

    /**
     * The file the admin sent with this message, at most $max bytes; null
     * (and a message why) if there is none, it is too big or does not load.
     * Telegram gives bots files up to 20 MB.
     */
    public function downloadInput(int $max): ?string
    {
        if (empty($this->input['file_id'])) {
            $this->send($this->input['chat'], 'send it as a file');
            return null;
        }
        $r    = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        $path = $r['result']['file_path'] ?? '';
        $mb   = round($max / 1048576, 1) . ' MB';
        if (($r['result']['file_size'] ?? 0) > $max) {
            $this->send($this->input['chat'], "the file is over $mb");
            return null;
        }
        $f = $path !== '' ? @fopen($this->file . $path, 'r') : false;
        // the size Telegram reports is optional: never more than $max read
        $s = $f ? stream_get_contents($f, $max + 1) : false;
        if ($f) {
            fclose($f);
        }
        if (!is_string($s)) {
            $this->send($this->input['chat'], 'cannot load the file');
            return null;
        }
        if (strlen($s) > $max) {
            $this->send($this->input['chat'], "the file is over $mb");
            return null;
        }
        return $s;
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

    public function cron()
    {
        $period = 10;
        while (true) {
            // each step on its own: an error in one (even a TypeError) must
            // not stop the loop or the steps after it
            foreach ([
                'checkVersion',
                'checkBackup',
                'rotateLogs',
                'checkResetXrayStats',
                'checkCert',
                'checkCertRenew',
                'writeAdguardInclude',
                'autoAnalyzeLogs',
                'xrayStatsUser',
                'ocTraffic',
                'checkWarpStatus',
            ] as $step) {
                try {
                    $this->$step();
                } catch (Throwable $e) {
                    error_log("cron $step: $e");
                }
            }
            // scripts/supervise.sh restarts the loop if this gets old
            @touch('/tmp/cron_heartbeat');
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

    /**
     * The backup schedule "start / period" (e.g. "2025-01-01 03:00 / 1 day"):
     * [start, period in seconds], or null if it is wrong. An hour at least:
     * every backup goes to every admin's chat.
     */
    public function backupSchedule($s): ?array
    {
        $p = array_map('trim', explode('/', (string) $s, 2));
        if (count($p) !== 2 || $p[0] === '' || $p[1] === '') {
            return null;
        }
        $start  = strtotime($p[0]);
        $period = strtotime($p[1], 0);
        return $start && $period >= 3600 ? [$start, $period] : null;
    }

    public function checkBackup()
    {
        $c = $this->getPacConf();
        if (empty($c['backup']) || !($b = $this->backupSchedule($c['backup']))) {
            return;
        }
        [$start, $period] = $b;
        $now = time();
        if ($now < $start) {
            return;
        }
        // the last scheduled time; one backup per period, also after a pause
        $due  = $start + intdiv($now - $start, $period) * $period;
        $done = false;
        $this->updateState(function ($st) use ($c, $due, $now, &$done) {
            // earlier versions kept the time in the settings
            if (($st['last_backup_time'] ?? $c['last_backup_time'] ?? 0) < $due) {
                $st['last_backup_time'] = $now;
                $done = true;
            }
            return $st;
        });
        if ($done) {
            $this->sendBackup();
        }
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


    public function cleanQueue(): void
    {
        $r = $this->request('deleteWebhook', []);
        $r = $this->request('getUpdates', ['offset' => -1]);
    }


    /**
     * Backups hold every key and password of the server and go to Telegram,
     * so they are encrypted. The server keeps no backup password, only a
     * public key: the password gives, through Argon2id, the seed of an
     * X25519 key pair; a backup is a sealed box for its public key and
     * only that password opens it again (restore asks for it).
     */
    const BACKUP_OPS = 3;
    const BACKUP_MEM = 67108864;

    // the backup public key and how it was made, [] if none is set
    public function backupKey(): array
    {
        $f = BOT_DATA . '/secrets/backup_key.json';
        return is_file($f) ? bot_read_json($f) : [];
    }

    public function setBackupKey(?string $pass)
    {
        $f = BOT_DATA . '/secrets/backup_key.json';
        if ($pass === null) {
            @unlink($f);
            return;
        }
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $kp   = $this->backupKeyPair($pass, $salt, self::BACKUP_OPS, self::BACKUP_MEM);
        bot_write_json($f, [
            'kdf'  => 'argon2id',
            'ops'  => self::BACKUP_OPS,
            'mem'  => self::BACKUP_MEM,
            'salt' => base64_encode($salt),
            'pk'   => base64_encode(sodium_crypto_box_publickey($kp)),
        ]);
        sodium_memzero($kp);
    }

    public function backupKeyPair(string $pass, string $salt, int $ops, int $mem): string
    {
        $seed = sodium_crypto_pwhash(SODIUM_CRYPTO_BOX_SEEDBYTES, $pass, $salt, $ops, $mem, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $kp   = sodium_crypto_box_seed_keypair($seed);
        sodium_memzero($seed);
        return $kp;
    }

    public function encryptBackup(string $plain): string
    {
        $k = $this->backupKey();
        return json_encode([
            'vpnbot_backup' => 2,
            'kdf'           => 'argon2id',
            'ops'           => (int) $k['ops'],
            'mem'           => (int) $k['mem'],
            'salt'          => $k['salt'],
            'cipher'        => 'x25519-xsalsa20poly1305-sealed',
            'pk'            => $k['pk'],
            'data'          => base64_encode(sodium_crypto_box_seal($plain, base64_decode($k['pk']))),
        ]);
    }

    /**
     * null: wrong password or damaged file. Version 2: sealed box (above);
     * version 1 (earlier backups): AES-256-GCM, key from PBKDF2-SHA256.
     * The work factors come from the file: only within bounds.
     */
    public function decryptBackup(array $env, string $pass): ?string
    {
        if ((int) ($env['vpnbot_backup'] ?? 0) === 2) {
            $ops  = (int) ($env['ops'] ?? 0);
            $mem  = (int) ($env['mem'] ?? 0);
            $salt = (string) base64_decode((string) ($env['salt'] ?? ''), true);
            if (!function_exists('sodium_crypto_pwhash') || ($env['kdf'] ?? '') !== 'argon2id' || $ops < 1 || $ops > 10
                || $mem < 8388608 || $mem > 268435456 || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
                return null;
            }
            $kp = $this->backupKeyPair($pass, $salt, $ops, $mem);
            if (!hash_equals((string) base64_decode((string) ($env['pk'] ?? '')), sodium_crypto_box_publickey($kp))) {
                return null;
            }
            $plain = sodium_crypto_box_seal_open((string) base64_decode((string) ($env['data'] ?? '')), $kp);
            sodium_memzero($kp);
            return $plain === false ? null : $plain;
        }
        if (($env['cipher'] ?? '') !== 'aes-256-gcm' || ($env['kdf'] ?? '') !== 'pbkdf2-sha256') {
            return null;
        }
        $iter  = max(100000, min(2000000, (int) ($env['iter'] ?? 0)));
        $key   = hash_pbkdf2('sha256', $pass, (string) base64_decode($env['salt'] ?? ''), $iter, 32, true);
        $plain = openssl_decrypt((string) base64_decode($env['data'] ?? ''), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, (string) base64_decode($env['iv'] ?? ''), (string) base64_decode($env['tag'] ?? ''));
        return $plain === false ? null : $plain;
    }

    // the encrypted backup to the main admin
    public function sendBackup()
    {
        $c = $this->config();
        if (!$this->backupKey()) {
            $this->send($c['admin'][0], 'backup not sent: set a backup password in Settings, backups are only sent encrypted');
            return;
        }
        $json = $this->export();
        $bot = preg_replace('~[\W]~iu', '_', $this->request('getMyName', [])['result']['name']);
        $this->sendFile($c['admin'][0], new CURLStringFile($this->encryptBackup($json), "{$bot}_backup_" . date('d_m_Y_H_i') . '.enc.json', 'application/json'));
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

    // the password message is deleted (reply()); only the public key stays
    public function setBackupPassword($text)
    {
        $text = trim((string) $text);
        if ($text === '-') {
            $this->setBackupKey(null);
        } elseif (!function_exists('sodium_crypto_pwhash')) {
            $this->send($this->input['chat'], 'no sodium in PHP: rebuild the images (Settings -> rebuild images)');
        } elseif (preg_match('~^[^\x00-\x1f\x7f]{8,128}$~uD', $text)) {
            $this->setBackupKey($text);
            $this->send($this->input['chat'], 'backup password set: it is not stored, keep it yourself; restoring a backup asks for it');
        } else {
            $this->send($this->input['chat'], 'wrong password: 8-128 printable characters');
        }
        $this->menu('config');
    }

    /**
     * New commits in the bot's own repository (origin, e.g. botlight), up to
     * $to (the tracked branch, or a tag). The host side scripts/update.sh
     * runs "git fetch" every hour, so here only the fetched refs are read.
     */
    public function newCommits($limit = 10, $to = '@{u}'): array
    {
        exec('git -C / log --no-merges --format=%s -n ' . (int) $limit . ' ' . escapeshellarg("HEAD..$to") . ' 2>/dev/null', $out);
        return array_values(array_filter(array_map('trim', $out)));
    }

    /**
     * The newest release tag after the running version on the tracked
     * branch: what the autoupdate installs (scripts/update.sh checks its
     * signature before anything stops).
     */
    public function newTag(): string
    {
        exec('git -C / tag --contains HEAD --merged @{u} --sort=-v:refname 2>/dev/null', $tags);
        exec('git -C / tag --points-at HEAD 2>/dev/null', $here);
        foreach ($tags as $t) {
            if (preg_match('~^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$~D', $t = trim($t)) && !in_array($t, array_map('trim', $here), true)) {
                return $t;
            }
        }
        return '';
    }

    // the key the release tags are signed with (scripts/update.sh, verify_tag)
    public function signingKey(): bool
    {
        return is_file(BOT_DATA . '/update-signing-key') && filesize(BOT_DATA . '/update-signing-key') > 0;
    }

    // the first admin, who started the bot: the only one for actions that
    // replace the bot or its admins
    public function isMainAdmin(): bool
    {
        try {
            $c = $this->adminConfig();
        } catch (Throwable $e) {
            return false;
        }
        return isset($c['admin'][0]) && $c['admin'][0] === (int) $this->input['from'];
    }

    public function mainAdminOnly(): bool
    {
        if ($this->isMainAdmin()) {
            return true;
        }
        if (!empty($this->input['callback_id'])) {
            $this->answer($this->input['callback_id'], 'only the main admin can do this', true);
        } else {
            $this->send($this->input['chat'], 'only the main admin can do this');
        }
        return false;
    }

    public function changelog()
    {
        $commits = $this->newCommits(30);
        $text    = $commits
            ? "New in " . htmlspecialchars(exec('git -C / rev-parse --abbrev-ref @{u} 2>/dev/null')) . ":\n\n- " . implode("\n- ", array_map(fn($e) => htmlspecialchars($e), $commits))
            : 'no updates';
        $this->send($this->input['chat'], $text);
    }

    public function checkVersion()
    {
        try {
            $c = $this->config();
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
                }
                // autoupdate: signed release tags only, never a plain commit
                $pac = $this->getPacConf();
                if (!empty($pac['autoupdate']) && $this->signingKey() && ($tag = $this->newTag()) !== '' && ($pac['autoupdate_tried'] ?? '') !== $tag) {
                    $pac['autoupdate_tried'] = $tag;
                    $this->setPacConf($pac);
                    $this->input['chat'] = $this->input['from'] = $c['admin'][0];
                    $this->send($c['admin'][0], "autoupdate to $tag:\n- " . implode("\n- ", array_map(fn($e) => htmlspecialchars($e), $this->newCommits(30, "refs/tags/$tag"))));
                    $this->startUpdate("tag:$tag");
                }
            }
        } catch (Throwable $e) {
            error_log("checkVersion: $e");
        }
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
        $i    = 0;
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
            'ad'  => $this->getAdguard(),
            'pac' => $this->exportPac(),
            'ssl' => file_exists('/certs/cert_private') && preg_match('~BEGIN (?:RSA |EC )?PRIVATE KEY~', file_get_contents('/certs/cert_private')) ? [
                'private' => file_get_contents('/certs/cert_private'),
                'public'  => file_get_contents('/certs/cert_public'),
            ] : false,
            'dnstt' => file_exists(BOT_DATA . '/dnstt/server.key') ? [
                'private' => bot_read(BOT_DATA . '/dnstt/server.key'),
                'public'  => bot_read(BOT_DATA . '/dnstt/server.pub'),
            ] : false,
            'xray'          => $this->getXray(),
            'oc'            => bot_read(BOT_DATA . '/ocserv/ocserv.conf'),
            'ocu'           => bot_read(BOT_DATA . '/ocserv/ocserv.passwd'),
            'xraystats'     => $this->getXrayStats(),
        ];
        return json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * The settings as a backup carries them (the format of earlier
     * versions): with the templates, which are kept apart now.
     */
    public function exportPac(): array
    {
        $pac = $this->getPacConf();
        foreach ($this->secrets() as $k => $v) {
            if ($k === 'reality_privateKey') {
                $pac['reality']['privateKey'] = $v;
            } elseif ($k !== 'oc_camouflage') {
                $pac[$k] = $v;
            }
        }
        foreach (['sing', 'clash'] as $type) {
            if ($t = $this->getTemplates($type)) {
                $pac["{$type}templates"] = $t;
            }
            $f = BOT_DATA . "/templates/$type.origin.json";
            if (is_file($f)) {
                $pac["{$type}origin"] = bot_read_json($f);
            }
        }
        return $pac;
    }

    // a backup's settings (or the old pac.json) into their places
    public function importPac(array $pac)
    {
        foreach (['sing', 'clash'] as $type) {
            if (isset($pac["{$type}templates"])) {
                $this->saveTemplates($type, is_array($pac["{$type}templates"]) ? $pac["{$type}templates"] : []);
            }
            if (!empty($pac["{$type}origin"]) && is_array($pac["{$type}origin"])) {
                bot_write_json(BOT_DATA . "/templates/$type.origin.json", $pac["{$type}origin"], 0660, BOT_GID_WEB);
            }
            unset($pac["{$type}templates"], $pac["{$type}origin"]);
        }
        $this->setPacConf($this->moveSecrets($pac));
        $this->writeWarpKey();
    }

    // restore: main admin only, after a confirmation
    public function import($yes = false)
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        if (empty($yes)) {
            return $this->update($this->input['chat'], $this->input['message_id'], $this->i18n('import') . "\n\nThe backup replaces the settings, users, keys and certificates of this server. Xray, AdGuard and OpenConnect restart.", [
                [['text' => $this->i18n('import'), 'callback_data' => '/import yes']],
                [['text' => $this->i18n('back'), 'callback_data' => '/menu config']],
            ]);
        }
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
        if (!$this->mainAdminOnly()) {
            return;
        }
        if (empty($this->input['file_id'])) {
            $this->send($this->input['chat'], 'send the backup as a file');
            return;
        }
        $this->importFile();
    }

    // reply with the password for an encrypted backup ($fileId from the prompt)
    /**
     * What is wrong with a backup (export()), before any of it is applied:
     * each part that is there must have the shape the import uses.
     */
    public function backupProblems(array $j): array
    {
        $p    = [];
        $pair = function ($v, $key, $pub) {
            return is_array($v) && is_string($v['private'] ?? null) && is_string($v['public'] ?? null)
                && preg_match($key, $v['private']) && preg_match($pub, $v['public']);
        };
        if (!array_intersect(['pac', 'ad', 'xray', 'oc', 'ssl', 'dnstt', 'xraystats'], array_keys(array_filter($j)))) {
            return ['not a backup of the bot'];
        }
        if (!empty($j['pac']) && !is_array($j['pac'])) {
            $p[] = 'pac: not an object';
        }
        if (!empty($j['ad']) && (!is_array($j['ad']) || !is_array($j['ad']['dns'] ?? null))) {
            $p[] = 'ad: not an AdGuard config';
        }
        if (!empty($j['xray']) && (!is_array($j['xray']) || !is_array($j['xray']['inbounds'][0]['settings']['clients'] ?? null))) {
            $p[] = 'xray: not an Xray config with clients';
        }
        if (!empty($j['xray']) && empty($j['pac'])) {
            $p[] = 'xray: without pac';
        }
        if (!empty($j['xraystats']) && !is_array($j['xraystats'])) {
            $p[] = 'xraystats: not an object';
        }
        if (!empty($j['oc']) && (!is_string($j['oc']) || !is_string($j['ocu'] ?? null))) {
            $p[] = 'oc: config or users missing';
        }
        if (!empty($j['ssl']) && !$pair($j['ssl'], '~-----BEGIN [A-Z ]*PRIVATE KEY-----~', '~-----BEGIN CERTIFICATE-----~')) {
            $p[] = 'ssl: not a key and certificate';
        }
        if (!empty($j['dnstt']) && !$pair($j['dnstt'], '~\S~', '~\S~')) {
            $p[] = 'dnstt: keys missing';
        }
        return $p;
    }

    public function importWithPassword($text, $fileId)
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        $this->input['file_id'] = $fileId;
        $this->importFile(false, trim((string) $text));
    }

    public function importFile($file = false, $password = null)
    {
        if (!empty($file)) {
            $json = json_decode(file_get_contents($file), true);
        } else {
            $f = $this->downloadInput(20 * 1048576);
            if ($f === null) {
                return;
            }
            $json = json_decode($f, true);
        }
        if (is_array($json) && !empty($json['vpnbot_backup'])) {
            // encrypted: the password is asked for (not kept on the server)
            $pass  = (string) $password;
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
        $problems = is_array($json) ? $this->backupProblems($json) : ['not a backup of the bot'];
        if ($problems && !empty($file)) {
            // the settings left by an earlier version (selfUpdate keeps a copy)
            throw new RuntimeException(implode('; ', $problems));
        }
        if ($problems) {
            // checked before anything is changed: a wrong file changes nothing
            $this->answer($this->input['callback_id'], 'error', true);
            $this->send($this->input['chat'], "import stopped, nothing changed:\n" . htmlspecialchars(implode("\n", $problems)));
        } else {
            // certs
            if (!empty($json['ssl'])) {
                $out[] = 'update certificates';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                bot_write('/certs/cert_private', (string) $json['ssl']['private'], 0600);
                bot_write('/certs/cert_public', (string) $json['ssl']['public'], 0644);
            }
            // pac
            if (!empty($json['pac'])) {
                $out[] = 'update pac';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->importPac($json['pac']);
            }
            // ad
            if (!empty($json['ad'])) {
                $out[] = 'update adguard';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->stopAd();
                $this->saveAdguard($json['ad']);
                $this->startAd();
            }
            // xray
            if (!empty($json['xray'])) {
                $out[] = 'update xray';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->restartXray($json['xray']);
                $this->adguardXrayClients();
                $this->setUpstreamDomain(($json['pac']['transport'] ?? null) != 'Reality' ? 't' : (($json['pac']['reality']['domain'] ?? null) ?: $json['xray']['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]));
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
                bot_write(BOT_DATA . '/ocserv/ocserv.passwd', (string) $json['ocu']);
                $this->restartOcserv($json['oc']);
            }
            if (!empty($json['pac']['domain'])) {
                $this->setUpstreamDomainOcserv($json['pac']['domain']);
            }
            // dnstt
            if (!empty($json['dnstt'])) {
                $out[] = 'update dnstt certificates';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                bot_write(BOT_DATA . '/dnstt/server.key', (string) $json['dnstt']['private']);
                bot_write(BOT_DATA . '/dnstt/server.pub', (string) $json['dnstt']['public'], 0644);
            }
            // nginx
            $out[] = 'reset nginx';
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));

            $this->cloakNginx();

            $out[] = "end import";
            $this->language = ($this->getPacConf()['language'] ?? null) ?: 'en';
            $this->limit    = ($this->getPacConf()['limitpage'] ?? null) ?: 5;
            if (empty($file)) {
                // the log stays as a message of its own, the menu goes back in place
                $this->send($this->input['chat'], implode("\n", $out));
                $this->menu();
            } else {
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
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
        $c = $this->config();
        $p  = $this->getPacConf();
        $ip = $this->ip;
        $r  = $this->send($c['admin'][0], "start $ip");

        $this->input['chat']        = $c['admin'][0];
        $this->input['message_id']  = $r['result']['message_id'];
        $this->input['callback_id'] = false;
        if (empty(array_diff_key($p, array_flip(['hashbot', 'oc_domain', 'adminhash', 'restart'])))) {
            // a fresh install: a nip.io name and a certificate for it
            $this->addDomain(str_replace('.', '-', $this->ip) . '.nip.io', 1);
            $this->certTask(false, (int) $c['admin'][0]);
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
        $email = (string) getenv('LE_EMAIL');
        $email = filter_var($email, FILTER_VALIDATE_EMAIL) ? '--email ' . escapeshellarg($email) : '--register-unsafely-without-email';
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

    /**
     * State of the cron loop (when it last made a backup, reset the stats,
     * checked the certificate): /data/state.json, apart from the settings
     * the bot writes, so the two processes do not overwrite each other.
     */
    public function getState(): array
    {
        $f = BOT_DATA . '/state.json';
        return is_file($f) ? bot_read_json($f) : [];
    }

    public function updateState(callable $fn): array
    {
        return bot_update_json(BOT_DATA . '/state.json', $fn, 0600, null, true);
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

    // the settings; an exception if they cannot be read (never defaults
    // that would then be written over them)
    public function getPacConf()
    {
        return bot_read_json($this->pac);
    }

    public function setPacConf(array $conf)
    {
        // read by the web pools (subscriptions)
        bot_write_json($this->pac, $conf, 0640, BOT_GID_WEB);
        return true;
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
        $ssl = $this->nginxGetTypeCert();
        $c   = $this->getAdguard();
        $this->stopAd();
        $c['users'] = [
            ['name' => 'admin', 'password' => password_hash($pass, PASSWORD_DEFAULT)],
            // nginx's login (writeAdguardInclude): a long random password, so
            // a fast hash is enough; AdGuard checks it on every request
            ['name' => 'bot', 'password' => password_hash($this->adguardProxyPassword(), PASSWORD_BCRYPT, ['cost' => 4])],
        ];
        $c = $this->adguardClientsConf($c);
        if (!empty($ssl) && !empty($pac['domain']) && empty($c['tls']['enabled'])) {
            $c['tls']['enabled']     = true;
            $c['tls']['server_name'] = $pac['domain'];
        }
        $this->saveAdguard($c);
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
        // the DoT name is in the certificate: a new one with it
        if (($c['letsencrypt'] ?? '') === 'letsencrypt') {
            $this->certTask(false);
            $this->send($this->input['chat'], 'the certificate is renewed for the new name: a message follows');
        }
        $this->menu('adguard');
    }

    public function enterAdmin()
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
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
        $c = $this->config();
        $c['admin']       = array_values(array_map('intval', (array) ($c['admin'] ?? [])));
        $c['admin_names'] = (array) ($c['admin_names'] ?? []);
        return $c;
    }

    public function saveAdminConfig(array $c)
    {
        bot_config_save($c);
        $this->writeWebSecrets();
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
        if (!$this->mainAdminOnly()) {
            return;
        }
        // an admin can do almost everything: confirmed first
        $_SESSION['add_admin'] = [(int) $m[1], $m[2]];
        $this->send($this->input['chat'], $this->i18n('add') . ' ' . $this->i18n('admin') . ': <code>' . (int) $m[1] . '</code> ' . htmlspecialchars($m[2]) . "?\nAn admin manages the whole server: users, keys, settings.", button: [
            [['text' => $this->i18n('yes'), 'callback_data' => '/addAdminYes ' . (int) $m[1]]],
            [['text' => $this->i18n('back'), 'callback_data' => '/menu config']],
        ]);
    }

    public function addAdminYes(int $id)
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        [$pid, $name] = $_SESSION['add_admin'] ?? [0, ''];
        unset($_SESSION['add_admin']);
        if ($pid !== $id || !$this->validName($name)) {
            return $this->menu('config');
        }
        $c = $this->adminConfig();
        if (!in_array($id, $c['admin'], true)) {
            $c['admin'][] = $id;
        }
        $c['admin_names'][$id] = $name;
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

    public function delAdmin($id, $yes = false)
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        $c = $this->adminConfig();
        $k = array_search((int) $id, $c['admin'], true);
        // never the main admin (the first one): the bot always keeps an
        // admin, with none left the next person to write to it would become
        // admin
        if ($k === false || $k === 0) {
            $this->answer($this->input['callback_id'], $k === false ? 'no such admin' : 'the main admin cannot be removed', true);
            return;
        }
        if (empty($yes)) {
            return $this->update($this->input['chat'], $this->input['message_id'], $this->i18n('delete') . ' ' . $this->i18n('admin') . ' ' . htmlspecialchars($this->adminLabel($c, (int) $id)) . '?', [
                [['text' => $this->i18n('yes'), 'callback_data' => "/deladmin $id yes"]],
                [['text' => $this->i18n('back'), 'callback_data' => "/adminCard $id"]],
            ]);
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
        // a message of its own, the menu goes back in place
        $this->send($this->input['chat'], mb_substr(($code ? '' : "JSON=1 dnslookup $dns\n") . implode("\n", $out), 0, 4000), mode: false);
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
     * AdGuard in the background. After a config change it must come up
     * within a few seconds, else the previous config goes back.
     */
    public function startAd()
    {
        $out = $this->ssh('/opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work', 'ad', false);
        if ($this->adguardChanged) {
            $this->adguardChanged = false;
            for ($i = 0; $i < 20 && !$this->adguardUp(); $i++) {
                usleep(500000);
            }
            if (!$this->adguardUp() && $this->rollbackConfig($this->adguard)) {
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


    // a short id that stays the same for a value (button data: 64 bytes at most)
    public function shortId(string $v): string
    {
        return substr(hash('sha256', $v), 0, 10);
    }

    public function i18n(string $menu): string
    {
        return ($this->i18n[$menu][$this->language] ?? '') ?: $menu;
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
        // the SSH password of the tunnel account, open to anyone who finds the domain
        if ($text && !$this->validSecret($text = trim((string) $text), 12)) {
            $this->send($this->input['chat'], 'wrong password: 12-128 printable characters, no ":"');
            return;
        }
        $this->setSecret('dnsttPassword', $text ? (string) $text : null);
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
        $c['dnsttPassword'] = $this->secret('dnsttPassword');
        $this->ssh('pkill dnstt', 'dnstt');
        // the domain goes into a background "sh -c" command: a host name only, quoted
        if (!empty($c['dnsttDomain']) && !empty($c['dnsttPassword']) && $this->validHost($c['dnsttDomain'])) {
            $this->ssh('echo ' . escapeshellarg("vpnbot:{$c['dnsttPassword']}") . ' | chpasswd', 'dnstt');
            if (!file_exists(BOT_DATA . '/dnstt/server.key')) {
                $this->ssh("dnstt-server -gen-key -privkey-file /dnstt/server.key -pubkey-file /dnstt/server.pub", 'dnstt');
            }
            $this->ssh('dnstt-server -udp :53 -privkey-file /dnstt/server.key ' . escapeshellarg($c['dnsttDomain']) . ' 127.0.0.1:22', 'dnstt', false, '/logs/dnstt');
        } else {
            // dnstt is off: the tunnel account must not keep an old password
            $this->ssh('passwd -l vpnbot', 'dnstt');
        }
    }

    public function dnsttDownload()
    {
        $this->sendFile($this->input['from'], curl_file_create(BOT_DATA . '/dnstt/server.pub'));
    }

    public function dnstt($update = false)
    {
        $c      = $this->getPacConf();
        $pubkey = (string) @file_get_contents(BOT_DATA . '/dnstt/server.pub');
        $text[] = "dnstt";
        if (!empty($c['dnsttDomain']) && $this->secret('dnsttPassword') !== '') {
            $text[] = "<pre>set the NS record for {$c['dnsttDomain']}: tns.{$c['domain']}\nset A record for tns.{$c['domain']}: {$this->ip}</pre>";
            // the password: in the Mini App (secrets)
            $text[] = 'account: <code>vpnbot</code>, password: ' . $this->mask($this->secret('dnsttPassword'));
            $text[] = "server name: <code>{$c['dnsttDomain']}</code>";
            $text[] = "public key: <code>$pubkey</code>";
            $data[] = [
                [
                    'text'          => $this->i18n('download pubkey'),
                    'callback_data' => "/dnsttDownload",
                ],
                $this->secretsButton('dnstt'),
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
        $domain = ($conf['domain'] ?? null) ?: $this->ip;
        $hash   = $this->getHashBot();
        if ($type == false) {
            $update = exec('git -C / rev-list --count HEAD..@{u}');
            $branch = exec('git -C / rev-parse --abbrev-ref HEAD');
            $backup = '';
            if (!empty($conf['backup'])) {
                $b      = array_map('trim', explode('/', $conf['backup'], 2));
                $backup = $this->backupSchedule($conf['backup']) ? "{$b[0]} start / {$b[1]} period" : htmlspecialchars($conf['backup']) . ' - wrong format';
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
                $this->i18n(!empty($ports['ad']['enable']) ? 'on' : 'off') . (!empty($ports['ad']['enable']) ? ' ' . $ports['ad']['port'] : ' port is closed'),
            ];
            if ($dnstt) {
                $status[]  = $this->i18n($this->ssh('pgrep dnstt', 'dnstt') ? 'on' : 'off') . ' ' . $this->i18n('dnstt');
                $portcol[] = $this->i18n(!empty($ports['dnstt']['enable']) ? 'on' : 'off') . (!empty($ports['dnstt']['enable']) ? ' ' . $ports['dnstt']['port'] : ' port is closed');
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

    public function switchBanIp()
    {
        $c = $this->getPacConf();
        $c['autodeny'] = !empty($c['autodeny']) ? 0 : 1;
        $this->setPacConf($c);
        $this->ipMenu();
    }

    // the monthly reset of Xray and OpenConnect traffic; $oc: from the OpenConnect menu
    public function switchMonthlyStats($oc = false)
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
        return $oc ? $this->menu('oc') : $this->xray();
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
        if ($r = @fopen($file, 'r')) {
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

    /**
     * Suspicious addresses in the access logs (not on the white or block
     * lists, not seen as clients): [ip => [[title, log], ...]]. Reads the
     * whole logs: run in the cron loop or in the background (task.php).
     */
    public function analysisScan(): array
    {
        $pac = $this->getPacConf();
        $xr  = [];
        foreach (array_merge(($pac['white'] ?? null) ?: [], ($pac['deny'] ?? null) ?: [], ['10.10.0.0/23']) as $v) {
            if (preg_match('~^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:(/\d{1,2}))?$~', $v, $m)) {
                if (!in_array($m[1] . (($m[2] ?? null) ?: '/32'), $xr)) {
                    $xr[] = $m[1] . (($m[2] ?? null) ?: '/32');
                }
            }
        }
        if ($r = @fopen('/logs/nginx_doh_access', 'r')) {
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
        if ($r = @fopen('/logs/xray', 'r')) {
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
        if (empty($fun)) {
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
        if (empty($fun)) {
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

    // a random UUID (v4)
    public function uuid(): string
    {
        $b    = random_bytes(16);
        $b[6] = chr(ord($b[6]) & 0x0f | 0x40);
        $b[8] = chr(ord($b[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
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
     * the WARP+ license key if given ("+": the current key, "-": none). It
     * is all made in /etc/warp/new first: only when everything worked does
     * it replace the running profile, and if WireGuard does not come up
     * with it, the previous profile goes back. The account file and the
     * profile never go into the chat.
     */
    public function addWarpPlus($key)
    {
        $chat = $this->input['chat'];
        $log  = '';
        $key  = trim((string) $key);
        if ($key === '+') {
            // re-registration with the current key
            $key = $this->secret('warp');
        } elseif ($key === '-') {
            $key = '';
        }
        // checked before anything starts: the key goes into a sed
        // expression, WARP+ keys are letters, digits and dashes
        if ($key !== '' && !preg_match('~^[A-Za-z0-9-]{1,64}$~D', $key)) {
            $this->send($chat, 'wrong license key');
            return $this->warp();
        }

        // a step in the wp container: the error (exit code, stderr) is shown, not the output
        $step = function ($label, $cmd) use ($chat, &$log) {
            $log .= "$label...";
            $this->sendDraft($chat, 1, $log);
            $r  = $this->sshRun($cmd, 'wp');
            $ok = $r['rc'] === 0;
            $log .= $ok ? " ok\n" : "\n" . htmlspecialchars(trim($r['err']) ?: ($r['rc'] === null ? 'no connection to wp' : "exit code {$r['rc']}")) . "\n";
            $this->sendDraft($chat, 1, $log);
            return $ok;
        };
        $fail = function () use ($chat, &$log) {
            $this->ssh('rm -rf /etc/warp/new', 'wp');
            $this->send($chat, $log . "\nnothing changed: WARP runs with the previous profile");
        };

        $d = '/etc/warp/new';
        if (!$step('registering a new WARP account', "rm -rf $d && mkdir -p $d && cd $d && wgcf register --accept-tos > /dev/null")) {
            return $fail();
        }
        if ($key !== '' && !$step('applying the license key', "cd $d && sed -i 's/^license_key.*/license_key = \"$key\"/' wgcf-account.toml && wgcf update > /dev/null")) {
            return $fail();
        }
        // no IPv6 (the container has none) and no DNS line (see start_wp.sh)
        if (!$step('generating the profile', "cd $d && wgcf generate > /dev/null && sed -i '/^Address.*:/d; /^AllowedIPs.*::/d; /^DNS *=/d' wgcf-profile.conf")) {
            return $fail();
        }
        $up = 'out=$(wg-quick up /etc/warp/wgcf-profile.conf 2>&1); ec=$?; [ "$ec" -ne 0 ] && printf "%s" "$out" | grep -v "skip sysctl" >&2; exit $ec';
        // the previous profile stays in old/ until the new one is up
        // (start_wp.sh goes back to it if the container restarts meanwhile)
        if (!$step('switching to the new profile', 'cd /etc/warp && wg-quick down /etc/warp/wgcf-profile.conf > /dev/null 2>&1; rm -rf old && mkdir old && { [ ! -f wgcf-profile.conf ] || cp -p wgcf-account.toml wgcf-profile.conf old/; } && mv new/wgcf-account.toml new/wgcf-profile.conf . && rmdir new')
            || !$step('starting warp', $up)) {
            // the new profile does not work here: the previous one back
            if ($step('back to the previous profile', 'cd /etc/warp && wg-quick down /etc/warp/wgcf-profile.conf > /dev/null 2>&1; rm -rf new; [ ! -f old/wgcf-profile.conf ] || cp -p old/wgcf-account.toml old/wgcf-profile.conf . ; ' . $up)) {
                $this->ssh('rm -rf /etc/warp/old', 'wp');
            }
            $this->send($chat, $log);
            return $this->warp();
        }
        $this->ssh('rm -rf /etc/warp/old', 'wp');
        $this->setSecret('warp', $key !== '' ? $key : null);
        $this->writeWarpKey();
        $this->syncWarpProfile();

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
        preg_match('~warp=(\w+)~', (string) $st, $m);
        return trim($m[1] ?? '') ?: 'off';
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

    /**
     * WARP: status and the masked WARP+ key. The account file (private key,
     * access token) and the WireGuard profile never go into the chat: the
     * key and the profile are in the Mini App (secrets).
     */
    public function warp()
    {
        $this->syncWarpProfile();
        $text[] = $this->i18n('Menu') . ' -> ' . $this->i18n('warp');
        // command output goes into an HTML message: escaped
        $text[] = "status: <pre>" . htmlspecialchars((string) $this->ssh('wgcf trace', 'wp')) . '</pre>';
        $text[] = 'warp+ key: ' . ($this->secret('warp') !== '' ? $this->mask($this->secret('warp')) : $this->i18n('off'));
        $data[] = [
            [
                'text'          => $this->i18n('warp+ / re-registration'),
                'callback_data' => "/warpPlus",
            ],
            $this->secretsButton('warp'),
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
        if (file_exists(__DIR__ . '/subscription.php')) {
            $text[] = "<a href='$scheme://{$domain}/pac$hash/sub?id={$c['id']}'>subscription</a>";
        }
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
                'text'          => $this->i18n('new subscription link'),
                'callback_data' => "/newSubXr $uid",
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
        if ($cdn && !empty($c['linkdomain'])) {
            return $c['linkdomain'];
        }
        return ($c['domain'] ?? null) ?: $this->ip;
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
        $singbox  = $this->subLink($scheme, $domain, 'si', $uid);
        $clash = $this->subLink($scheme, $domain, 'cl', $uid);
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
        // the user first: nothing else is read for an unknown or disabled one
        $xr     = $this->getXray();
        $flag = true;
        $client = null;
        $sid = is_string($_GET['s'] ?? null) ? $_GET['s'] : '';
        foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($sid !== '' && hash_equals((string) $v['id'], $sid)) {
                if (empty($v['off'])) {
                    $flag = false;
                }
                $template = base64_decode((string) ($v["{$type}template"] ?? ''));
                $uid      = $v['id'];
                $email    = $v['email'];
                $client   = $v;
                break;
            }
        }
        if ($flag) {
            header('404', true, 404);
            exit;
        }
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
        if (!empty($return)) {
            if (($_GET['t'] ?? null) == 'cl') {
                return yaml_emit($c);
            }
            return json_encode($c);
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

    /**
     * What the Mini App pool needs instead of the bot token: the key that
     * checks Telegram's initData signature (it cannot call the Bot API),
     * the admins and the AdGuard cookie. /data/secrets: botadmin only.
     */
    public function writeWebSecrets()
    {
        $c = $this->adminConfig();
        bot_write_json(BOT_DATA . '/secrets/web.json', [
            'initdata_key'   => hash_hmac('sha256', $this->key, 'WebAppData'),
            'admins'         => $c['admin'],
            'adguard_cookie' => $this->getAdguardCookie(),
        ], 0640, BOT_GID_SECRET);
    }

    public function webSecrets(): array
    {
        return bot_read_json(BOT_DATA . '/secrets/web.json');
    }

    /**
     * Passwords and keys (/data/secrets/secrets.json, readable by root and
     * the Mini App pool only): adpswd and adguard_proxy (AdGuard), ocserv
     * and oc_camouflage (OpenConnect), dnsttPassword, warp (WARP+ key),
     * reality_privateKey.
     * Not in pac.json, which the public web pool reads.
     */

    public function secrets(): array
    {
        $f = BOT_DATA . '/secrets/secrets.json';
        return is_file($f) ? bot_read_json($f) : [];
    }

    public function secret(string $name): string
    {
        return (string) ($this->secrets()[$name] ?? '');
    }

    // a secret in the chat: only its last 4 characters (••••-AB12)
    public function mask(string $v): string
    {
        if ($v === '') {
            return $this->i18n('off');
        }
        return '••••' . (mb_strlen($v) > 8 ? '-' . htmlspecialchars(mb_substr($v, -4)) : '');
    }

    /**
     * The button to a menu's secrets: the Mini App (only over HTTPS with a
     * valid certificate: Telegram opens Mini Apps by https only), else they
     * are shown once in the chat and deleted after a minute.
     */
    public function secretsButton(string $section): array
    {
        $domain = $this->getPacConf()['domain'] ?? '';
        if ($this->nginxGetTypeCert() && $domain !== '') {
            return [
                'text'    => '🔑 ' . $this->i18n('secrets'),
                'web_app' => ['url' => "https://$domain/webapp{$this->getAdminHash()}/secrets?s=$section"],
            ];
        }
        return [
            'text'          => '🔑 ' . $this->i18n('secrets'),
            'callback_data' => "/secrets $section",
        ];
    }

    // the secrets of a menu for the Mini App and the shown-once message
    public function secretsOf(string $section): array
    {
        $pac    = $this->getPacConf();
        $domain = $this->getDomain();
        switch ($section) {
            case 'adguard':
                return [
                    'AdGuard login'    => 'admin',
                    'AdGuard password' => $this->secret('adpswd'),
                ];
            case 'ocserv':
                $cs = $this->secret('oc_camouflage');
                return [
                    'OpenConnect password' => $this->secret('ocserv'),
                    'OpenConnect link'     => 'https://' . $this->getHashSubdomain('oc') . ".$domain/" . ($cs !== '' ? "?$cs" : ''),
                ];
            case 'dnstt':
                return [
                    'DNSTT account'  => 'vpnbot',
                    'DNSTT password' => $this->secret('dnsttPassword'),
                    'DNSTT domain'   => (string) ($pac['dnsttDomain'] ?? ''),
                ];
            case 'warp':
                // the key only: the profile is a download in the Mini App
                return ['WARP+ key' => $this->secret('warp')];
        }
        return [];
    }

    // without HTTPS: the secrets in a message that is deleted after 60 s
    public function showSecrets(string $section)
    {
        $text = [];
        foreach ($this->secretsOf($section) as $k => $v) {
            $text[] = htmlspecialchars($k) . ': ' . ($v !== '' ? '<code>' . htmlspecialchars($v) . '</code>' : '—');
        }
        $r = $this->send($this->input['chat'], implode("\n", $text ?: ['—']) . "\n\n<i>deleted in a minute</i>", disable_notification: true);
        if (!empty($r['result']['message_id'])) {
            $this->deleteLater($this->input['chat'], $r['result']['message_id'], 60);
        }
        $this->answer($this->input['callback_id']);
    }

    // messages to delete later; the polling loop does it (deleteDue)
    public function deleteLater($chat, $message, int $seconds)
    {
        $this->later[] = [$chat, $message, time() + $seconds];
    }

    public function deleteDue()
    {
        foreach ($this->later as $k => [$chat, $message, $at]) {
            if ($at <= time()) {
                $this->delete($chat, $message);
                unset($this->later[$k]);
            }
        }
    }

    /**
     * A copy of the WARP WireGuard profile for the Mini App download: the
     * warp volume is root only, the copy is in /data/secrets.
     */
    public function syncWarpProfile()
    {
        $p = @file_get_contents('/etc/warp/wgcf-profile.conf');
        $f = BOT_DATA . '/secrets/warp-profile.conf';
        if (is_string($p) && $p !== '' && $p !== @file_get_contents($f)) {
            bot_write($f, $p, 0640, BOT_GID_SECRET);
        } elseif (($p === false || $p === '') && is_file($f) && !is_file('/etc/warp/wgcf-profile.conf')) {
            @unlink($f);
        }
    }

    // '' or null removes it
    public function setSecret(string $name, ?string $value)
    {
        bot_update_json(BOT_DATA . '/secrets/secrets.json', function ($s) use ($name, $value) {
            if ($value === null || $value === '') {
                unset($s[$name]);
            } else {
                $s[$name] = $value;
            }
            return $s;
        }, 0640, BOT_GID_SECRET, true);
    }

    /**
     * Secrets kept in the settings by earlier versions (or in a backup) go
     * to secrets.json; the plain backup password becomes the backup key.
     * Returns the settings without them.
     */
    public function moveSecrets(array $pac): array
    {
        foreach (['adpswd', 'ocserv', 'dnsttPassword', 'warp', 'adguard_proxy'] as $k) {
            if (array_key_exists($k, $pac)) {
                $this->setSecret($k, is_scalar($pac[$k]) ? (string) $pac[$k] : null);
                unset($pac[$k]);
            }
        }
        if (isset($pac['reality']['privateKey'])) {
            $this->setSecret('reality_privateKey', (string) $pac['reality']['privateKey']);
            unset($pac['reality']['privateKey']);
        }
        if (array_key_exists('backup_password', $pac)) {
            if (is_string($pac['backup_password'] ?? null) && $pac['backup_password'] !== '' && function_exists('sodium_crypto_pwhash')) {
                $this->setBackupKey($pac['backup_password']);
            }
            if (function_exists('sodium_crypto_pwhash')) {
                unset($pac['backup_password']);
            }
        }
        return $pac;
    }

    public function getHashBot($notset = false)
    {
        $p = $this->getPacConf();
        if (!empty($p['hashbot'])) {
            return $p['hashbot'];
        }
        // secret path part for /pac, /webapp, /adguard, /ws: 128 bits, derived
        // from the bot token, stored on first use
        if ($this->web) {
            throw new RuntimeException('no path hash in the settings');
        }
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
    // printable, no ":" (it goes into chpasswd and ocserv.passwd); $min characters at least
    public function validSecret($secret, int $min = 1): bool
    {
        return is_string($secret) && (bool) preg_match('~^[^\x00-\x1f\x7f:]{' . max(1, $min) . ',128}$~uD', $secret);
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
        return $this->getDomain(($pac['transport'] ?? null) != 'Reality');
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
        if ($conf['domain'] && $conf['letsencrypt']) {
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
                access_log /logs/nginx_adguard_access;
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

    /**
     * Secret path part of the admin's pages (/webapp, /adguard): 128 random
     * bits, not derived from anything subscribers see.
     */
    public function getAdminHash(): string
    {
        $p = $this->getPacConf();
        if (!empty($p['adminhash']) && preg_match('~^[0-9a-f]{32}$~D', $p['adminhash'])) {
            return $p['adminhash'];
        }
        if ($this->web) {
            throw new RuntimeException('no admin path in the settings');
        }
        $p['adminhash'] = bin2hex(random_bytes(16));
        $this->setPacConf($p);
        return $p['adminhash'];
    }

    public function getHashSubdomain($subdomain)
    {
        $p = $this->getPacConf();
        if (isset($p["{$subdomain}_domain"])) {
            return $p["{$subdomain}_domain"];
        }
        if ($this->web) {
            return '';
        }
        $p["{$subdomain}_domain"] = substr(hash('sha256', "$subdomain{$this->key}"), 0, 8);
        $this->setPacConf($p);
        return $p["{$subdomain}_domain"];
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
        return $this->certTimes()['to'] ?? false;
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

    public function updatebot()
    {
        $b = exec('git -C / rev-parse --abbrev-ref HEAD');
        $track  = trim((string) @file_get_contents('/update/branch'));
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
        $tag  = $this->newTag();
        $info = "\nrelease signing key: " . ($this->signingKey() ? 'set' : 'not set (autoupdate is off)')
            . ($tag !== '' ? "\nnew release: " . htmlspecialchars($tag) : '');
        return [
            'text' => '<pre><code class="language-shell">' . htmlentities(implode("\n", $mm)) . '</code></pre>' . $info,
            'data' => $data,
        ];
    }

    /**
     * The update button: what comes (changelog) and a confirmation first;
     * only the main admin installs it.
     */
    public function applyupdatebot($yes = false)
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        if (empty($yes)) {
            $commits = $this->newCommits(30);
            $branch  = trim((string) @file_get_contents('/update/branch'));
            $current = exec('git -C / rev-parse --abbrev-ref HEAD 2>/dev/null');
            $text    = $this->i18n('Menu') . ' -> ' . $this->i18n('update bot') . "\n\n";
            if ($branch !== '' && $branch !== $current) {
                $text .= 'branch: ' . htmlspecialchars("$current → $branch") . "\n\n";
            }
            $text .= $commits
                ? "- " . implode("\n- ", array_map(fn($e) => htmlspecialchars($e), $commits))
                : 'no new commits';
            $text .= "\n\nThe bot and the VPN stop for the update (a minute or more). Settings in ./data are kept.";
            return $this->update($this->input['chat'], $this->input['message_id'], $text, [
                [['text' => $this->i18n('update bot'), 'callback_data' => '/applyupdatebot yes']],
                [['text' => $this->i18n('back'), 'callback_data' => '/menu update']],
            ]);
        }
        $this->startUpdate('');
    }

    // $target: "tag:<name>" (a signed release) or '' (the tracked branch)
    public function startUpdate(string $target)
    {
        // the latest traffic into the stats: Xray stops for the update
        $this->xrayStatsUser(true);
        bot_write('/update/target', $target);
        $this->hostCommand('1', 'update...');
    }

    public function restart()
    {
        $this->xrayStatsUser(true);
        $this->hostCommand('2', 'restart...');
    }

    public function rebuildMenu()
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
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
        if (!$this->mainAdminOnly()) {
            return;
        }
        $this->xrayStatsUser(true);
        $this->sendBackup();
        $this->hostCommand('3', 'rebuild images...');
    }

    // hands a command to scripts/update.sh on the host: 1 update, 2 restart,
    // 3 rebuild images
    public function hostCommand($cmd, $draft)
    {
        $r = $this->sendDraft($this->input['from'], 1, $draft);
        bot_write('/update/reload_message', "{$this->input['from']}:{$r['result']['message_id']}");
        // the token for the "bot started" message; cleared by update.sh
        bot_write('/update/key', $this->key, 0600);
        bot_write('/update/curl', json_encode([
            'chat_id'    => $this->input['chat'],
            'message_id' => $r['result']['message_id'],
            'text'       => '~t~'
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        bot_write('/update/pipe', $cmd);
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
                    'text'          => !empty($conf['domain']) ? "{$this->i18n('delete')} {$conf['domain']}" : $this->i18n('install domain'),
                    'callback_data' => !empty($conf['domain']) ? '/deldomain' : '/domain',
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
        // cover page at the site root ("fake html")
        $fake   = is_file(BOT_DATA . '/www/override.html');
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

    public function branches()
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        foreach ($this->remoteBranches() as $id => $v) {
            $data[] = [
                [
                    'text'          => $v,
                    'callback_data' => "/changeBranch $id",
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

    // origin's branches by a short id that stays the same (button data)
    public function remoteBranches(): array
    {
        exec('git -C / branch -r --format="%(refname:short)" 2>/dev/null', $m);
        $r = [];
        foreach ($m as $v) {
            $v = trim($v);
            if (preg_match('~^origin/([A-Za-z0-9._/-]+)$~D', $v, $b) && $b[1] !== 'HEAD' && $b[1][0] !== '-') {
                $r[hash('crc32b', $b[1])] = $b[1];
            }
        }
        return $r;
    }

    /**
     * The branch the next update switches to: main admin only, after a
     * confirmation (another branch can be another bot).
     */
    public function changeBranch($id, $yes = false)
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        $branch = $this->remoteBranches()[$id] ?? null;
        if ($branch === null) {
            return $this->branches();
        }
        if (empty($yes)) {
            return $this->update($this->input['chat'], $this->input['message_id'], $this->i18n('manage updates') . "\n\n" . 'track branch <b>' . htmlspecialchars($branch) . '</b>? The next update (update bot) switches to it.', [
                [['text' => $this->i18n('yes'), 'callback_data' => "/changeBranch $id yes"]],
                [['text' => $this->i18n('back'), 'callback_data' => '/branches']],
            ]);
        }
        bot_write('/update/branch', $branch);
        $this->menu('update');
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

    /**
     * After an update: the message of scripts/update.sh. Versions before
     * ./data reset the repository on update and left a plain settings
     * backup in /update/json, restored here once (this happens on the
     * first update to this version: the old update.sh does it). The file
     * is removed either way: it holds every key in plain text. A backup is
     * applied only over default settings; if the settings were changed
     * since, they are kept.
     */
    public function selfUpdate()
    {
        $rm = explode(':', trim((string) @file_get_contents('/update/reload_message')));
        $m  = trim((string) @file_get_contents('/update/message'));
        bot_write('/update/message', '');
        bot_write('/update/reload_message', '');
        $c = $this->config();
        $chat = preg_match('~^-?\d+$~D', $rm[0] ?? '') ? (int) $rm[0] : (int) ($c['admin'][0] ?? 0);
        $to   = preg_match('~^\d+$~D', $rm[1] ?? '') ? (int) $rm[1] : null;
        if ($m !== '') {
            $this->send($chat, '<pre>' . htmlspecialchars($m) . '</pre>', $to);
        }
        if (file_exists($this->update)) {
            $this->selfupdate = true;
            if ($this->defaultSettings()) {
                $r = $this->send($chat, "import settings");
                $this->input['chat']        = $chat;
                $this->input['message_id']  = $r['result']['message_id'] ?? 0;
                $this->input['callback_id'] = false;
                try {
                    $this->importFile($this->update);
                } catch (Throwable $e) {
                    // a copy only root can read, outside the folder the containers write to
                    $kept = BOT_DATA . '/backup/legacy-update-' . date('Ymd-His') . '.json';
                    @mkdir(BOT_DATA . '/backup', 0700);
                    bot_write($kept, bot_read($this->update), 0600);
                    $this->send($chat, 'import settings failed: ' . htmlspecialchars($e->getMessage()) . "\nthe settings are kept in data/backup/" . basename($kept) . ' (plain text: delete it once restored)');
                }
            } else {
                $this->send($chat, 'a settings backup from ' . date('Y-m-d H:i', (int) filemtime($this->update)) . ' was not applied: the current settings are not the defaults, so they were kept');
            }
            @unlink($this->update);
        }
        // copies the earlier versions kept
        foreach (glob('/update/json.{failed,unapplied}-*', GLOB_BRACE) ?: [] as $f) {
            @unlink($f);
        }
        $pac = $this->getPacConf();
        unset($pac['restart']);
        $this->setPacConf($pac);
    }

    // settings as after a repository reset: Xray config of the repository, no own settings in pac.json
    public function defaultSettings(): bool
    {
        $repo = @file_get_contents('/config/xray.json');
        if (!empty($repo) && json_decode($repo, true) == $this->getXray()) {
            return true;
        }
        return !array_diff_key($this->getPacConf() ?: [], array_flip(['hashbot', 'oc_domain', 'restart', 'adminhash', 'debug_until']));
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

    public function setBackup($text)
    {
        $text = trim($text);
        $c    = $this->getPacConf();
        if (empty($text)) {
            $c['backup'] = '';
        } elseif ($b = $this->backupSchedule($text)) {
            $c['backup'] = implode(' / ', [date('Y-m-d H:i', $b[0]), trim(explode('/', $text, 2)[1])]);
        } else {
            $this->send($this->input['from'], htmlspecialchars($text) . ' - wrong format, the period is an hour at least');
        }
        $this->setPacConf($c);
        $this->menu('config');
    }


    /**
     * Debug for 30 minutes (it turns itself off): the web pools log the
     * shape of requests (debug.php, values masked), SSH errors come to the
     * chat. The switch lives in the settings: the web pools cannot read
     * config.php. Main admin only.
     */
    public function debug()
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        $p = $this->getPacConf();
        if ($this->debugOn()) {
            unset($p['debug_until']);
        } else {
            $p['debug_until'] = time() + 1800;
        }
        $this->setPacConf($p);
        $this->menu('config');
    }

    public function debugOn(): bool
    {
        try {
            return (int) ($this->getPacConf()['debug_until'] ?? 0) > time();
        } catch (Throwable $e) {
            return false;
        }
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

    // autoupdate installs signed release tags only: not without the key
    public function autoupdate()
    {
        $p = $this->getPacConf();
        if (empty($p['autoupdate']) && !$this->signingKey()) {
            return $this->answer($this->input['callback_id'], 'autoupdate needs the release signing key: put it into data/update-signing-key on the server (see HARDENING.md)', true);
        }
        $p['autoupdate'] = empty($p['autoupdate']);
        $this->setPacConf($p);
        $this->menu('config');
    }

    // stdout of a command in a container (see sshRun)
    public function ssh($cmd, $service, $wait = true, $log = '/dev/null')
    {
        return $this->sshRun($cmd, $service, $wait, $log)['out'];
    }

    /**
     * A command in a container over SSH. Returns ['out' => stdout,
     * 'err' => stderr, 'rc' => exit code]; rc is null when the container
     * could not be reached or the command was started in the background
     * ($wait false, its output goes to $log).
     */
    public function sshRun($cmd, $service, $wait = true, $log = '/dev/null'): array
    {
        $res = ['out' => '', 'err' => '', 'rc' => null];
        try {
            $c = @ssh2_connect($service, 22, ['hostkey' => 'ssh-ed25519']);
            if (empty($c)) {
                throw new Exception("no connection to $service");
            }
            // the container must show its own host key (made by php, ./sshhost)
            $pub = preg_match('~^[a-z]+$~', $service) ? @file_get_contents("/ssh/host_$service.pub") : false;
            $blob = base64_decode(explode(' ', trim((string) $pub))[1] ?? '', true);
            if (!$blob || strcasecmp(ssh2_fingerprint($c, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_HEX), sha1($blob)) !== 0) {
                error_log("ssh $service: host key mismatch, command not sent");
                throw new Exception("host key mismatch: $service");
            }
            $a = @ssh2_auth_pubkey_file($c, 'root', '/ssh/key.pub', '/ssh/key');
            if (empty($a)) {
                throw new Exception("auth fail: $service");
            }

            if (!$wait) {
                // nohup: independent of the SSH session, & in the background,
                // the output into $log and the container's log
                $cmd = "nohup sh -c \"$cmd 2>&1 | tee -a $log >&3\" 3>/proc/1/fd/1 </dev/null &";
            } else {
                // the exit code comes as the last line of stdout; the
                // subshell keeps it even if the command calls exit
                $cmd = "(\n$cmd\n)\nprintf '\\n__botrc=%d' \"\$?\"";
            }

            $s = ssh2_exec($c, $cmd);
            if (empty($s)) {
                throw new Exception("exec fail: $service");
            }

            if ($wait) {
                // both streams without blocking: a blocking read of stdout
                // does not see its end while stderr is open (php-ssh2), and
                // a process left in the background may keep stdout open;
                // the exit code line ends the command
                $e = ssh2_fetch_stream($s, SSH2_STREAM_STDERR);
                stream_set_blocking($s, false);
                stream_set_blocking($e, false);
                $deadline = time() + 300;
                while (true) {
                    $o = fread($s, 8192);
                    $r = fread($e, 8192);
                    $res['out'] .= (string) $o;
                    $res['err'] .= (string) $r;
                    if (preg_match('~\n__botrc=(\d+)$~', $res['out'], $m)) {
                        $res['rc']  = (int) $m[1];
                        $res['out'] = substr($res['out'], 0, -strlen($m[0]));
                        break;
                    }
                    if (feof($s) || time() > $deadline) {
                        break;
                    }
                    if ((string) $o === '' && (string) $r === '') {
                        usleep(20000);
                    }
                }
                // what is left on stderr
                for ($i = 0; $i < 5; $i++) {
                    $r = fread($e, 8192);
                    if ((string) $r !== '') {
                        $res['err'] .= $r;
                        $i = 0;
                    } else {
                        usleep(10000);
                    }
                }
                fclose($e);
            } else {
                // a moment for the background command to start
                stream_set_blocking($s, false);
                usleep(100000);
            }

            fclose($s);
            ssh2_disconnect($c);
        } catch (Exception | Error $e) {
            $res['err'] = $e->getMessage();
            if ($this->debugOn()) {
                $this->send($this->input['chat'], htmlspecialchars("ssh $service: " . $e->getMessage()), $this->input['message_id']);
            }
        }
        return $res;
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
            try {
                $offset = $this->pollingRound($offset);
            } catch (Throwable $e) {
                error_log("polling: $e");
                sleep(3);
            }
        }
    }

    // one getUpdates and its updates; the next offset
    public function pollingRound(int $offset): int
    {
        $r = $this->request('getUpdates', [
            'offset'          => $offset,
            'limit'           => 3,
            'timeout'         => 5,
            // explicit: without it Telegram keeps the list from an
            // earlier webhook or bot on this token, which may leave out
            // button presses (callback_query)
            'allowed_updates' => json_encode(['message', 'callback_query', 'inline_query', 'channel_post', 'my_chat_member']),
        ]);
        // the loop is alive: healthcheck and scripts/supervise.sh read it
        @touch('/tmp/heartbeat');
        $this->deleteDue();
        if (empty($this->time_warp_profile) || time() - $this->time_warp_profile > 600) {
            $this->time_warp_profile = time();
            $this->syncWarpProfile();
        }
        if (!empty($r['description'])) {
            error_log('getUpdates error: ' . $r['description']);
            sleep(3);
            return $offset;
        }
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
        return $offset;
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
                    // no link previews: messages carry subscription links
                    'link_preview_options'     => json_encode(['is_disabled' => true]),
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
                'link_preview_options'     => json_encode(['is_disabled' => true]),
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
            'link_preview_options'     => json_encode(['is_disabled' => true]),
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
