<?php

// Long jobs in the background, started by the bot or the cron loop:
//   php task.php cert force|due CHAT   (Bot::certTask)
require __DIR__ . '/timezone.php';

require __DIR__ . '/storage.php';
$c = bot_config();
require __DIR__ . '/bot.php';
require __DIR__ . '/i18n.php';

$bot = new Bot($c['key'], $i);
switch ($argv[1] ?? '') {
    case 'cert':
        $chat = (int) ($argv[3] ?? 0);
        // one certbot at a time, in either container (php or service)
        $ran = bot_try_lock(BOT_DATA . '/certbot', function () use ($bot, $argv, $chat) {
            try {
                $bot->renewCert(($argv[2] ?? '') === 'force', $chat);
            } catch (Throwable $e) {
                error_log("task cert: $e");
                $bot->send($chat ?: (int) ($bot->config()['admin'][0] ?? 0), 'certificate: ' . htmlspecialchars($e->getMessage()));
            }
        });
        if (!$ran && $chat) {
            $bot->send($chat, 'certificate: certbot is already running');
        }
        break;
}
