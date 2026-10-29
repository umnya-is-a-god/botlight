<?php

// the methods by area, as traits (app/bot/)
require_once __DIR__ . '/bot/telegram.php';
require_once __DIR__ . '/bot/remote.php';
require_once __DIR__ . '/bot/settings.php';
require_once __DIR__ . '/bot/xray.php';
require_once __DIR__ . '/bot/subscriptions.php';
require_once __DIR__ . '/bot/lists.php';
require_once __DIR__ . '/bot/adguard.php';
require_once __DIR__ . '/bot/openconnect.php';
require_once __DIR__ . '/bot/warp.php';
require_once __DIR__ . '/bot/dnstt.php';
require_once __DIR__ . '/bot/domain.php';
require_once __DIR__ . '/bot/logs.php';
require_once __DIR__ . '/bot/backup.php';
require_once __DIR__ . '/bot/update.php';
require_once __DIR__ . '/bot/admin.php';
require_once __DIR__ . '/bot/menu.php';

class Bot
{
    use BotTelegram,
        BotRemote,
        BotSettings,
        BotXray,
        BotSubscription,
        BotLists,
        BotAdguard,
        BotOpenconnect,
        BotWarp,
        BotDnstt,
        BotDomain,
        BotLogs,
        BotBackup,
        BotUpdate,
        BotAdmin,
        BotMenu;

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
    public $time_status;

    /**
     * Backups hold every key and password of the server and go to Telegram,
     * so they are encrypted. The server keeps no backup password, only a
     * public key: the password gives, through Argon2id, the seed of an
     * X25519 key pair; a backup is a sealed box for its public key and
     * only that password opens it again (restore asks for it).
     */
    const BACKUP_OPS = 3;
    const BACKUP_MEM = 67108864;

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
                'statusCache',
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

    // a random UUID (v4)
    public function uuid(): string
    {
        $b    = random_bytes(16);
        $b[6] = chr(ord($b[6]) & 0x0f | 0x40);
        $b[8] = chr(ord($b[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
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

}
