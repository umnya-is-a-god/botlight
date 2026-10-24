<?php

// Before the bot starts (scripts/start_php.sh): see Bot::prepare()
require __DIR__ . '/timezone.php';

require __DIR__ . '/storage.php';
bot_prepare_files();
$c = bot_config();
require __DIR__ . '/bot.php';
require __DIR__ . '/i18n.php';

(new Bot($c['key'], $i))->prepare();
