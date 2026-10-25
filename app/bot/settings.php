<?php

// Settings, state and secrets in /data; the hashes in the URL paths: methods of class Bot (app/bot.php)
trait BotSettings
{
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
}
