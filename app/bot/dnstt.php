<?php

// DNSTT tunnel: methods of class Bot (app/bot.php)
trait BotDnstt
{
    public function dnsttDomain()
    {
        $this->prompt($this->i18n('enter domain'), $this->i18n('enter domain'), 'setdnsttDomain');
    }

    public function dnsttPassword()
    {
        $this->prompt($this->i18n('enter password'), $this->i18n('enter password'), 'setdnsttPassword');
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
}
