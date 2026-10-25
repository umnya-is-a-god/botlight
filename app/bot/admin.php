<?php

// Admins, debug mode: methods of class Bot (app/bot.php)
trait BotAdmin
{
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

    public function enterAdmin()
    {
        if (!$this->mainAdminOnly()) {
            return;
        }
        $this->prompt($this->i18n('enter id / name'), $this->i18n('ph: enter id / name'), 'addAdmin');
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
        $this->prompt($this->i18n('enter name'), $this->i18n('enter name'), 'setAdminName', [(int) $id]);
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
}
