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
     * with it, the previous profile goes back. The tunnel is down while
     * wgcf talks to Cloudflare's API: through a tunnel that does not work
     * the API does not answer either. The account file and the profile
     * never go into the chat.
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
        $up = 'out=$(wg-quick up /etc/warp/wgcf-profile.conf 2>&1); ec=$?; [ "$ec" -ne 0 ] && printf "%s" "$out" | grep -v "skip sysctl" >&2; exit $ec';
        $fail = function () use ($chat, &$log, $step, $up) {
            $this->ssh('rm -rf /etc/warp/new', 'wp');
            if (!$step('starting warp with the previous profile', 'ip link show wgcf-profile > /dev/null 2>&1 || [ ! -f /etc/warp/wgcf-profile.conf ] || { ' . $up . '; }')) {
                return $this->send($chat, $log);
            }
            $this->send($chat, $log . "\nnothing changed: WARP runs with the previous profile");
        };

        $d = '/etc/warp/new';
        // wgcf goes to the API directly; clients going out through WARP wait meanwhile
        if (!$step('stopping warp (clients through it wait)', 'wg-quick down /etc/warp/wgcf-profile.conf > /dev/null 2>&1; ! ip link show wgcf-profile > /dev/null 2>&1')) {
            return $fail();
        }
        if (!$step('registering a new WARP account', "rm -rf $d && mkdir -p $d && cd $d && wgcf register --accept-tos > /dev/null")) {
            return $fail();
        }
        if ($key !== '' && !$step('applying the license key', "cd $d && sed -i 's/^license_key.*/license_key = \"$key\"/' wgcf-account.toml && wgcf update > /dev/null")) {
            return $fail();
        }
        // IPv4 only, no DNS line (scripts/warp_profile.sh, also used by start_wp.sh)
        if (!$step('generating the profile', "cd $d && wgcf generate > /dev/null && sh /scripts/warp_profile.sh wgcf-profile.conf")) {
            return $fail();
        }
        // up is not enough: Cloudflare must see the traffic come through WARP
        $works = 'for i in 1 2 3 4 5; do wgcf trace 2>/dev/null | grep -qE "^warp=(on|plus)$" && exit 0; sleep 2; done; echo "WARP does not answer through the new profile" >&2; exit 1';
        // the previous profile stays in old/ until the new one is up
        // (start_wp.sh goes back to it if the container restarts meanwhile)
        if (!$step('switching to the new profile', 'cd /etc/warp && wg-quick down /etc/warp/wgcf-profile.conf > /dev/null 2>&1; rm -rf old && mkdir old && { [ ! -f wgcf-profile.conf ] || cp -p wgcf-account.toml wgcf-profile.conf old/; } && mv new/wgcf-account.toml new/wgcf-profile.conf . && rmdir new')
            || !$step('starting warp', $up)
            || !$step('checking warp', $works)) {
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
        // the menu shows the new account's exit, not the cached one
        $this->checkWarpStatus(true);

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
     * in a file (status, then the exit: address · country (data centre));
     * the menus only read it. One failed check is not enough for off: a
     * request through WARP now and then takes longer than the timeout.
     */
    public function checkWarpStatus($force = false)
    {
        if ($force || empty($this->time_warp_status) || time() - $this->time_warp_status > 60) {
            $this->time_warp_status = time();
            $f     = '/logs/.warp_status';
            $trace = $this->warpTrace();
            $st    = $this->warpStatus($trace);
            if ($st === 'off' && !$force && ++$this->warp_fails < 2 && is_file($f)) {
                // the previous answer stays, still fresh for cachedWarpStatus()
                @touch($f);
                return;
            }
            $this->warp_fails = 0;
            $exit = $st === 'off' ? '' : ($trace['ip'] ?? '?') . ' · ' . ($trace['loc'] ?? '?') . ' (' . ($trace['colo'] ?? '?') . ')';
            file_put_contents("$f.tmp", "$st\n$exit\n");
            rename("$f.tmp", $f);
        }
    }

    // [status, exit]; no answer for 3 minutes (cron stopped): treat as off
    public function cachedWarp(): array
    {
        $f = '/logs/.warp_status';
        if (is_file($f) && time() - filemtime($f) < 180) {
            $l = explode("\n", (string) file_get_contents($f));
            if (preg_match('~^\w+$~', trim($l[0]))) {
                return [trim($l[0]), trim($l[1] ?? '')];
            }
        }
        return ['off', ''];
    }

    public function cachedWarpStatus()
    {
        return $this->cachedWarp()[0];
    }

    // on, plus (WARP+) or off, from warpTrace() (made now if not given)
    public function warpStatus(?array $trace = null)
    {
        $trace ??= $this->warpTrace();
        return preg_match('~^\w+$~', $trace['warp'] ?? '') ? $trace['warp'] : 'off';
    }

    /**
     * Cloudflare's trace (key => value: warp, ip, loc, colo, ...) through
     * the WARP socks proxy, like Xray's warp outbound (the name is resolved
     * by microsocks); a request through WARP can take a few seconds.
     * 1.1.1.1 does not work here: HTTP redirects, HTTPS hangs
     */
    public function warpTrace(): array
    {
        $st = $this->ssh('curl -s -m 8 -x socks5h://wp:1080 https://cloudflare.com/cdn-cgi/trace', 'xr');
        preg_match_all('~^(\w+)=(.*)$~m', (string) $st, $m);
        return array_combine($m[1], array_map('trim', $m[2]));
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
        // from the cron check (checkWarpStatus): a check now takes seconds
        [$st, $exit] = $this->cachedWarp();
        $text[] = 'status: ' . ($st === 'off' ? $this->i18n('off') . ' off' : $this->i18n('on') . ' ' . ($st === 'plus' ? 'WARP+' : 'on'));
        if ($st !== 'off' && $exit !== '') {
            // where the traffic leaves WARP: address, country, Cloudflare data centre
            $text[] = 'exit: ' . htmlspecialchars($exit);
        }
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
