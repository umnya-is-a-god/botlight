<?php

// Commands in the other containers (SSH) and configs applied with a test and a way back: methods of class Bot (app/bot.php)
trait BotRemote
{
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
}
