<?php

// Backups (encrypted), export and import: methods of class Bot (app/bot.php)
trait BotBackup
{
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
    // true when the backup reached the main admin
    public function sendBackup(): bool
    {
        $c = $this->config();
        if (!$this->backupKey()) {
            $this->send($c['admin'][0], 'backup not sent: set a backup password in Settings, backups are only sent encrypted');
            return false;
        }
        $json = $this->export();
        $bot = preg_replace('~[\W]~iu', '_', $this->request('getMyName', [])['result']['name']);
        $r = $this->sendFile($c['admin'][0], new CURLStringFile($this->encryptBackup($json), "{$bot}_backup_" . date('d_m_Y_H_i') . '.enc.json', 'application/json'));
        return !empty($r['ok']);
    }

    /**
     * scripts/update.sh asks for a backup ("request" in ./update/backup)
     * before it stops the bot for an update or new images, only when there
     * is something to install. The answer goes back in the same file:
     * sent, no password or failed.
     */
    public function hostBackup()
    {
        if (trim((string) @file_get_contents('/update/backup')) !== 'request') {
            return;
        }
        bot_write('/update/backup', 'busy');
        try {
            $answer = $this->sendBackup() ? 'sent' : ($this->backupKey() ? 'failed' : 'no password');
        } catch (Throwable $e) {
            error_log("hostBackup: $e");
            $answer = 'failed';
        }
        bot_write('/update/backup', $answer);
    }

    public function backupPassword()
    {
        $this->prompt($this->i18n('prompt backup password'), $this->i18n('backup password'), 'setBackupPassword');
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
        $this->prompt($this->i18n('send the export file:'), $this->i18n('send the export file:'), 'importFromChat');
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
                $this->prompt($this->i18n('backup password'), $this->i18n('backup password'), 'importWithPassword', [$this->input['file_id']]);
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
                // the camouflage secret, for the Mini App (as prepare() does)
                if (preg_match('~^camouflage_secret\s*=\s*"([^"\n]*)"~m', bot_read(BOT_DATA . '/ocserv/ocserv.conf'), $m)) {
                    $this->setSecret('oc_camouflage', $m[1]);
                }
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


    public function backup()
    {
        $this->prompt($this->i18n('enter like: start / period'), $this->i18n('enter like: now / 12 hours'), 'setBackup');
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
}
