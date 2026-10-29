<?php

// The Mini App's sign-in check (app/webauth.php): initData signed the way
// Telegram signs it, for an admin, not too old.

require __DIR__ . '/lib.php';
require __DIR__ . '/../app/webauth.php';

$token = '123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw';
// Telegram: secret key = HMAC-SHA256 of the bot token with the key "WebAppData"
$secret = hash_hmac('sha256', $token, 'WebAppData', true);
$ws     = ['initdata_key' => bin2hex($secret), 'admins' => [111, 222]];

// initData as the Telegram client makes it, signed with $key
function init_data(array $fields, string $key): string
{
    ksort($fields);
    $check = implode("\n", array_map(fn($k, $v) => "$k=$v", array_keys($fields), $fields));
    return http_build_query($fields + ['hash' => hash_hmac('sha256', $check, $key)]);
}

$user  = fn(int $id) => json_encode(['id' => $id, 'first_name' => 'A']);
$fresh = ['auth_date' => (string) time(), 'query_id' => 'AAA', 'user' => $user(111)];

check('admin, fresh, signed: accepted', webapp_admin($ws, init_data($fresh, $secret)) === 111);
check('second admin: accepted', webapp_admin($ws, init_data(['user' => $user(222)] + $fresh, $secret)) === 222);
check('not an admin: refused', webapp_admin($ws, init_data(['user' => $user(333)] + $fresh, $secret)) === null);
check('signed with another key: refused', webapp_admin($ws, init_data($fresh, hash_hmac('sha256', 'other:token', 'WebAppData', true))) === null);
$d = init_data($fresh, $secret);
check('a field changed after signing: refused', webapp_admin($ws, str_replace('query_id=AAA', 'query_id=AAB', $d)) === null);
check('another user put in after signing: refused', webapp_admin($ws, preg_replace('~user=[^&]+~', 'user=' . rawurlencode($user(222)), $d)) === null);
check('an hour old: refused', webapp_admin($ws, init_data(['auth_date' => (string) (time() - 3600)] + $fresh, $secret)) === null);
check('59 minutes old: accepted', webapp_admin($ws, init_data(['auth_date' => (string) (time() - 3540)] + $fresh, $secret)) === 111);
check('from the future: refused', webapp_admin($ws, init_data(['auth_date' => (string) (time() + 120)] + $fresh, $secret)) === null);
check('no hash: refused', webapp_admin($ws, http_build_query($fresh)) === null);
check('empty: refused', webapp_admin($ws, '') === null);
check('not a string: refused', webapp_admin($ws, ['x']) === null);
check('over 4 KB: refused', webapp_admin($ws, init_data(['pad' => str_repeat('a', 5000)] + $fresh, $secret)) === null);
check('array field: refused', webapp_admin($ws, $d . '&x[]=1') === null);
check('no key on the server: refused', webapp_admin(['admins' => [111]], $d) === null);
check('no admins on the server: refused', webapp_admin(['initdata_key' => bin2hex($secret)], $d) === null);

done();
