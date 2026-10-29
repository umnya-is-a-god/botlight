<?php

// Who becomes admin (Bot::auth through Bot::input): the first user to write
// in a private chat, nobody else, nobody over a missing or damaged config.
// Writes to /data: run it on a test machine or in CI only.

require __DIR__ . '/lib.php';
require __DIR__ . '/../app/storage.php';
require __DIR__ . '/../app/bot.php';

if (realpath(BOT_DATA) === false || !is_writable(BOT_DATA) || file_exists(BOT_DATA . '/xray')) {
    echo "needs an empty writable " . BOT_DATA . " (not a bot's data)\n";
    exit(1);
}

// no Telegram, no containers: the requests are recorded, the actions only noted
class TestBot extends Bot
{
    public $sent = [];
    public $acted = false;

    public function request($method, $data, $json_header = 0)
    {
        $this->sent[] = $method;
        return ['ok' => true, 'result' => ['message_id' => 1]];
    }

    public function sshRun($cmd, $service, $wait = true, $log = '/dev/null'): array
    {
        return ['out' => '', 'err' => '', 'rc' => null];
    }

    public function session()
    {
    }

    public function action()
    {
        $this->acted = true;
    }
}

function update(int $from, string $chatType = 'private', bool $callback = false): array
{
    $chat = ['id' => $chatType === 'private' ? $from : -100, 'type' => $chatType];
    $user = ['id' => $from, 'username' => 'u', 'first_name' => 'Anna'];
    return $callback
        ? ['update_id' => 1, 'callback_query' => ['id' => 'c', 'data' => '/menu', 'from' => $user, 'message' => ['message_id' => 5, 'chat' => $chat, 'text' => '']]]
        : ['update_id' => 1, 'message' => ['message_id' => 5, 'text' => '/start', 'from' => $user, 'chat' => $chat]];
}

function run(array $update): TestBot
{
    $bot = new TestBot('', []);
    $bot->input($update);
    return $bot;
}

function admins(): array
{
    try {
        return bot_config()['admin'] ?? [];
    } catch (Throwable $e) {
        return ['unreadable'];
    }
}

// the bot's own messages about the broken configs below stay out of the output
ini_set('error_log', '/dev/null');
$cfg = BOT_DATA . '/config.php';
file_put_contents(BOT_DATA . '/pac.json', '{}');
@mkdir(BOT_DATA . '/secrets', 0750);

// no config.php: nobody is admin, nothing is written
@unlink($cfg);
$b = run(update(111));
check('no config.php: no admin, no action', !$b->admin && !$b->acted && !file_exists($cfg));

// a damaged config.php (no key): the same
file_put_contents($cfg, "<?php\n\$c = [];\n");
$b = run(update(111));
check('config without the key: no admin, file unchanged', !$b->admin && !$b->acted && file_get_contents($cfg) === "<?php\n\$c = [];\n");

// a fresh install: the key, no admins yet
bot_config_save(['key' => '123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw']);
$b = run(update(111, 'group'));
check('group chat: does not become admin', !$b->admin && admins() === []);
$b = run(update(111, 'supergroup'));
check('supergroup: does not become admin', !$b->admin && admins() === []);
$b = run(update(111, 'channel'));
check('channel: does not become admin', !$b->admin && admins() === []);
$b = run(update(111, 'private', true));
check('first contact by a button, not a message: not admin', !$b->admin && admins() === []);
$b = run(update(111));
check('first private message: becomes the main admin', $b->admin && $b->acted && admins() === [111]);
check('its name is kept', (bot_config()['admin_names'][111] ?? '') === 'Anna');
check('the Mini App learns the admin (web.json)', in_array(111, json_decode((string) @file_get_contents(BOT_DATA . '/secrets/web.json'), true)['admins'] ?? [], true));

// after that
$b = run(update(222));
check('another user: not admin, no action', !$b->admin && !$b->acted && admins() === [111]);
$b = run(update(111, 'private', true));
check('the admin by a button: admin', $b->admin && $b->acted);
$b = run(update(111, 'group'));
check('the admin in a group: ignored', !$b->admin && !$b->acted);
$b = run(update(0));
check('no sender id: not admin', !$b->admin && !$b->acted);

done();
