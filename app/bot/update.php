<?php

// Bot updates, branches, restart, image rebuild: methods of class Bot (app/bot.php)
trait BotUpdate
{
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

    /**
     * What "update bot" moves to: the tracked branch (@{u}), or
     * origin/<branch> when another branch is chosen in manage updates.
     */
    public function updateTarget(): string
    {
        $branch  = trim((string) @file_get_contents('/update/branch'));
        $current = (string) exec('git -C / rev-parse --abbrev-ref HEAD 2>/dev/null');
        if ($branch !== '' && $branch !== $current && preg_match('~^[A-Za-z0-9._][A-Za-z0-9._/-]{0,99}$~D', $branch)) {
            return "origin/$branch";
        }
        return '@{u}';
    }

    // "v1.1 → v1.2" when the update changes VERSION, '' otherwise
    public function versionChange(string $to): string
    {
        $old = trim((string) exec('git -C / show HEAD:VERSION 2>/dev/null'));
        $new = trim((string) exec('git -C / show ' . escapeshellarg("$to:VERSION") . ' 2>/dev/null'));
        return $new !== '' && $new !== $old ? htmlspecialchars("v$old → v$new") : '';
    }

    public function changelog()
    {
        $to      = $this->updateTarget();
        $commits = $this->newCommits(30, $to);
        $text    = $commits
            ? "New in " . htmlspecialchars(exec('git -C / rev-parse --abbrev-ref ' . escapeshellarg($to) . ' 2>/dev/null')) . ":\n\n- " . implode("\n- ", array_map(fn($e) => htmlspecialchars($e), $commits))
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

    // branch and commits behind origin: git is asked once a minute at most
    public function gitState(): array
    {
        static $c = null;
        if ($c === null || time() - $c['time'] > 60) {
            $c = [
                'time'   => time(),
                'behind' => (int) exec('git -C / rev-list --count HEAD..@{u} 2> /dev/null'),
                'branch' => (string) exec('git -C / rev-parse --abbrev-ref HEAD 2> /dev/null'),
            ];
        }
        return $c;
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
            // on another branch: what that branch has and this one has not
            $to      = $this->updateTarget();
            $commits = $this->newCommits(30, $to);
            $current = exec('git -C / rev-parse --abbrev-ref HEAD 2>/dev/null');
            $text    = $this->i18n('Menu') . ' -> ' . $this->i18n('update bot') . "\n\n";
            if (($v = $this->versionChange($to)) !== '') {
                $text .= "$v\n";
            }
            if ($to !== '@{u}') {
                $text .= 'branch: ' . htmlspecialchars($current . ' → ' . substr($to, strlen('origin/'))) . "\n";
            }
            $text .= "\n" . ($commits
                ? "- " . implode("\n- ", array_map(fn($e) => htmlspecialchars($e), $commits))
                : 'no new commits');
            // and what the running version has that the other branch has not
            $gone = (int) exec('git -C / rev-list --no-merges --count ' . escapeshellarg("$to..HEAD") . ' 2>/dev/null');
            if ($to !== '@{u}' && $gone > 0) {
                $text .= "\n\nnot in that branch: $gone commits of the running version";
            }
            // the host fetches hourly (scripts/update.sh): the list is as of then
            $fetched = @filemtime('/.git/FETCH_HEAD');
            if ($fetched) {
                $text .= "\n(as of " . date('Y-m-d H:i', $fetched) . '; the update itself takes the latest)';
            }
            $text .= "\n\nThe bot and the VPN stop for the update (a minute or more). Settings in ./data are kept; if there is something new, a backup is sent before the stop.";
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

    /**
     * The images the registry has newer versions of: scripts/images.sh
     * check, run daily on the host, leaves them in ./update/images.
     */
    public function newImages(): array
    {
        $s = trim((string) @file_get_contents('/update/images'));
        return array_values(array_filter(explode(' ', $s), fn($e) => (bool) preg_match('~^[a-z]{2,8}$~D', $e)));
    }

    // cron: the main admin is told once about each new set of images
    public function checkImages()
    {
        $new = implode(' ', $this->newImages());
        $this->updateState(function ($st) use ($new) {
            if ($new !== '' && ($st['images_notified'] ?? '') !== $new) {
                $admin = (int) ($this->config()['admin'][0] ?? 0);
                if ($admin) {
                    $this->send($admin, "new images on GitHub: $new\nSettings -> " . $this->i18n('update images'));
                }
            }
            $st['images_notified'] = $new;
            return $st;
        });
    }

    public function rebuildMenu()
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        $new = $this->newImages();
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $this->i18n('Menu') . ' -> ' . $this->i18n('config') . ' -> ' . $this->i18n('update images') . "\n\n"
            . ($new ? 'New on GitHub: ' . implode(', ', $new) . "\n\n" : "No new images found on the last daily check.\n\n")
            . "The images are built and checked on GitHub every week (fresh Alpine, AdGuard Home, Xray). "
            . "The new ones are downloaded while the VPN keeps working, then the containers restart (about a minute). "
            . "If they are not all running and healthy within 5 minutes, the previous images come back by themselves. "
            . "If GitHub cannot be reached, the images are built here instead: several minutes, the VPN is off meanwhile. "
            . "Settings and data are kept; if there are new images, a backup is sent before the restart.",
            [
                [['text' => $this->i18n('update images'), 'callback_data' => '/rebuildYes']],
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
        $this->hostCommand('3', 'update images...');
    }

    /**
     * scripts/update.sh is done (update, restart, images): the menu the
     * admin started from, as a new message under its report. It leaves
     * "chat:menu" in ./update/menu; read once, for an admin only.
     */
    public function menuAfterHost()
    {
        $s = trim((string) @file_get_contents('/update/menu'));
        if ($s === '') {
            return;
        }
        bot_write('/update/menu', '');
        if (!preg_match('~^(-?\d{1,20}):(config|update)$~D', $s, $m)
            || !in_array((int) $m[1], array_map('intval', $this->config()['admin'] ?? []), true)) {
            return;
        }
        $this->input = ['chat' => (int) $m[1], 'from' => (int) $m[1], 'message_id' => null, 'callback_id' => false, 'callback' => false, 'message' => '', 'username' => ''];
        $this->menu($m[2]);
    }

    // hands a command to scripts/update.sh on the host: 1 update, 2 restart,
    // 3 new images
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
                $kept = $this->keepLegacyUpdate($this->update, 'unapplied-' . date('Ymd-His', (int) filemtime($this->update)));
                $this->send($chat, 'a settings backup from ' . date('Y-m-d H:i', (int) filemtime($this->update)) . ' was not applied: the current settings are not the defaults, so they were kept'
                    . ($kept ? "\nthe backup is kept in data/backup/$kept (plain text: delete it once not needed)" : ''));
            }
            @unlink($this->update);
        }
        // copies the earlier versions kept in ./update (writable by the
        // containers): moved where only root reads them, never just deleted
        foreach (glob('/update/json.{failed,unapplied}-*', GLOB_BRACE) ?: [] as $f) {
            if ($this->keepLegacyUpdate($f, 'old-' . basename($f))) {
                @unlink($f);
            }
        }
        $pac = $this->getPacConf();
        unset($pac['restart']);
        $this->setPacConf($pac);
    }

    // a plain settings file of an earlier version into data/backup (root only); its name there, or '' if it could not be copied
    public function keepLegacyUpdate(string $file, string $suffix): string
    {
        $name = 'legacy-update-' . preg_replace('~[^A-Za-z0-9._-]~', '_', $suffix) . '.json';
        try {
            @mkdir(BOT_DATA . '/backup', 0700);
            bot_write(BOT_DATA . "/backup/$name", bot_read($file), 0600);
            return $name;
        } catch (Throwable $e) {
            error_log("keepLegacyUpdate $file: $e");
            return '';
        }
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

    // autoupdate installs signed release tags only: not without the key
    public function autoupdate()
    {
        $p = $this->getPacConf();
        if (empty($p['autoupdate']) && !$this->signingKey()) {
            return $this->answer($this->input['callback_id'], 'autoupdate needs the release signing key: put it into data/update-signing-key on the server (a GPG public key or an SSH allowed signers line)', true);
        }
        $p['autoupdate'] = empty($p['autoupdate']);
        $this->setPacConf($p);
        $this->menu('config');
    }
}
