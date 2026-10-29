<?php

/*
 * The Mini App's sign-in check (webapp.php): Telegram's initData, signed
 * with the key derived from the bot token (web.json: initdata_key), issued
 * for an admin, at most an hour old. Apart from webapp.php so tests can
 * load it (tests/webapp_auth_test.php).
 */

// the admin's Telegram id, or null
function webapp_admin(array $ws, $initData): ?int
{
    if (!is_string($initData) || $initData === '' || strlen($initData) > 4096) {
        return null;
    }
    parse_str($initData, $t);
    $hash = $t['hash'] ?? '';
    unset($t['hash']);
    if (!is_string($hash) || $hash === '') {
        return null;
    }
    ksort($t);
    $s = [];
    foreach ($t as $k => $v) {
        if (!is_string($v)) {
            return null;
        }
        $s[] = "$k=$v";
    }
    $key = (string) hex2bin((string) ($ws['initdata_key'] ?? ''));
    $age = time() - (int) ($t['auth_date'] ?? 0);
    $id  = (int) (json_decode($t['user'] ?? '', true)['id'] ?? 0);
    if ($key === '' || !hash_equals(hash_hmac('sha256', implode("\n", $s), $key), $hash)
        // an hour at most; none from the future (a minute of clock skew)
        || $age >= 3600 || $age < -60
        || $id <= 0 || !in_array($id, array_map('intval', (array) ($ws['admins'] ?? [])), true)) {
        return null;
    }
    return $id;
}
