<?php

require __DIR__ . '/timezone.php';
require __DIR__ . '/storage.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/i18n.php';
if (file_exists(__DIR__ . '/override.php')) {
    include __DIR__ . '/override.php';
}
// The web pools (system/php-fpm.conf) run without the bot token and read
// only what they need: the public pool answers the subscriptions, the
// admin pool the Mini App (Telegram sign-in on every request, webapp.php)
$pool = getenv('BOT_POOL') === 'admin' ? 'admin' : 'public';
$bot  = new Bot('', $i, true);
if ($bot->debugOn()) {
    require __DIR__ . '/debug.php';
}
$path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);

if ($pool === 'admin') {
    require __DIR__ . '/webapp.php';
    exit;
}

/**
 * Parameters of a sing-box/mihomo link from its last path part (sing-box
 * import links cannot carry a query): base64url JSON, or the base64 PHP
 * array of earlier versions, so links already handed out keep working.
 */
function sub_params(string $part): array
{
    if ($part === '' || strlen($part) > 1024) {
        return [];
    }
    $t = json_decode((string) base64_decode(strtr($part, '-_', '+/'), true), true);
    if (!is_array($t)) {
        $t = @unserialize((string) base64_decode($part, true), ['allowed_classes' => false, 'max_depth' => 2]);
    }
    $r = [];
    foreach (['t', 's', 'r'] as $k) {
        if (is_array($t) && isset($t[$k]) && is_scalar($t[$k])) {
            $r[$k] = (string) $t[$k];
        }
    }
    return $r;
}

$hash = $bot->getHashBot();
switch (true) {
    case str_starts_with($path, "/pac$hash/sub") && file_exists(__DIR__ . '/subscription.php'):
        $bot->sub();
        exit;

    // subs & pac
    case $path === "/pac$hash" || str_starts_with($path, "/pac$hash/"):
        foreach (sub_params(explode('/', $path)[2] ?? '') as $k => $v) {
            $_GET[$k] = $v;
        }
        switch (is_string($_GET['t'] ?? null) ? $_GET['t'] : '') {
            case 's':
            case 'si':
            case 'cl':
                $bot->subscription();
                exit;

            case 'hp':
                $bot->happSubscription();
                exit;

            default:
                header('404', true, 404);
                exit;
        }

    default:
        header('404', true, 404);
}
