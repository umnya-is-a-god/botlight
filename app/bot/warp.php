<?php

// WARP: account, WARP+ key, status: methods of class Bot (app/bot.php)
trait BotWarp
{
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

    public function warpPlus()
    {
        $this->prompt($this->i18n('prompt warp'), $this->i18n('enter key'), 'addWarpPlus');
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
}
