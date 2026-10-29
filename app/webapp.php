<?php

/*
 * The admin's Mini App: php-fpm pool "admin", /webapp<admin path>/...
 * (index.php). Whatever reads or changes settings takes Telegram's
 * initData from the POST body: signed with the bot token (the pool only
 * has the key derived from it), issued for an admin, at most an hour old.
 * Nothing here is cached.
 */

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/webauth.php';

$base = '/webapp' . $bot->getAdminHash();
if (!str_starts_with($path, "$base/")) {
    header('404', true, 404);
    exit;
}
$route = substr($path, strlen($base));
$post  = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST';
$admin = $post ? webapp_admin($bot->webSecrets(), $_POST['initData'] ?? null) : null;
$templateTypes = ['sing', 'clash'];
$js = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE;

switch ($route) {
    // AdGuard panel: the cookie nginx checks on /adguard<admin path>/
    case '/check':
        if ($admin === null) {
            header('403', true, 403);
            break;
        }
        setcookie('c', $bot->getAdguardCookie(), [
            'expires'  => time() + 86400,
            'path'     => '/adguard' . $bot->getAdminHash() . '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        echo '/adguard' . $bot->getAdminHash() . '/';
        break;

    // template editor: the page has no data, it loads the template with initData
    case '/editor':
        $ty = $_GET['ty'] ?? '';
        $te = is_string($_GET['te'] ?? null) ? $_GET['te'] : '';
        if (!in_array($ty, $templateTypes, true)) {
            header('404', true, 404);
            break;
        }
        header('Content-Type: text/html');
        $name = json_encode($te !== '' ? $te : 'origin', $js);
        $tyjs = json_encode($ty, $js);
        $save = json_encode($bot->i18n('save'), $js);
        $ok   = json_encode($bot->i18n('success'), $js);
        $err  = json_encode($bot->i18n('error'), $js);
        echo <<<HTML
            <!DOCTYPE HTML>
            <html lang="en" style="height:100%">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="$base/jsoneditor.min.css" rel="stylesheet" type="text/css">
                <script src="$base/jsoneditor.min.js"></script>
                <script src="https://telegram.org/js/telegram-web-app.js"></script>
            </head>
            <body style="height:100%">
                <div id="jsoneditor" style="height:100%"></div>
                <script>
                    var tg = window.Telegram.WebApp;
                    var name = $name, type = $tyjs;
                    // a form POST to this page's server, the reply as JSON; an error status fails
                    function post(url, data) {
                        return fetch(url, {method: 'POST', body: new URLSearchParams(data)}).then(function (r) {
                            if (!r.ok) {
                                throw r;
                            }
                            return r.json();
                        });
                    }
                    const editor = new JSONEditor(document.getElementById("jsoneditor"), {});
                    // the template is only sent to an admin's signed Telegram session
                    post('$base/load', {initData: tg.initData, name: name, type: type}).then(function (t) {
                        editor.set(t);
                    }).catch(function () {
                        document.getElementById("jsoneditor").textContent = 'access denied';
                    });
                    tg.MainButton.show().setText($save).onClick(function () {
                        post('$base/save', {initData: tg.initData, name: name, type: type, json: editor.getText()}).then(function (r) {
                            if (r.status == true) {
                                tg.MainButton.setText($ok);
                                setTimeout(() => { tg.close(); }, 500);
                            } else {
                                tg.MainButton.setText(r.message);
                            }
                        }).catch(function () {
                            tg.MainButton.setText($err);
                        });
                    });
                </script>
            </body>
            </html>
            HTML;
        break;

    // load template (editor)
    case '/load':
        $ty = $_POST['type'] ?? '';
        $te = $_POST['name'] ?? '';
        if ($admin === null || !in_array($ty, $templateTypes, true) || !is_string($te)) {
            header('403', true, 403);
            break;
        }
        $t = $te !== '' && $te !== 'origin'
            ? ($bot->getTemplates($ty)[$te] ?? null)
            : $bot->originTemplate($ty);
        header('Content-Type: application/json');
        echo json_encode($t ?? new stdClass(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        break;

    // save template (editor)
    case '/save':
        header('Content-Type: application/json');
        if ($admin === null) {
            header('403', true, 403);
            echo json_encode(['status' => false, 'message' => 'access denied']);
            break;
        }
        if (!in_array($_POST['type'] ?? '', $templateTypes, true) || !is_string($_POST['name'] ?? null) || $_POST['name'] === '' || !is_string($_POST['json'] ?? null)) {
            echo json_encode(['status' => false, 'message' => 'wrong template']);
            break;
        }
        echo json_encode($bot->saveTemplate($_POST['name'], $_POST['type'], $_POST['json']));
        break;

    // secrets: a page without data; the values come by POST with initData
    case '/secrets':
        header('Content-Type: text/html');
        $title = json_encode($bot->i18n('secrets'), $js);
        echo <<<HTML
            <!DOCTYPE HTML>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <script src="https://telegram.org/js/telegram-web-app.js"></script>
                <style>
                    body { font-family: sans-serif; margin: 16px; color: var(--tg-theme-text-color, #000); background: var(--tg-theme-bg-color, #fff); }
                    .item { margin: 0 0 14px; }
                    .label { font-size: 13px; opacity: .7; }
                    .value { font-family: monospace; word-break: break-all; padding: 6px 0; }
                    button { padding: 6px 12px; }
                </style>
            </head>
            <body>
                <h3 id="title"></h3>
                <div id="list">...</div>
                <script>
                    var tg = window.Telegram.WebApp;
                    var list = document.getElementById('list');
                    document.getElementById('title').textContent = $title;
                    var q = new URLSearchParams(location.search);
                    // an element with its text (never parsed as HTML)
                    function el(tag, cls, text) {
                        var e = document.createElement(tag);
                        e.className = cls;
                        e.textContent = text;
                        return e;
                    }
                    function button(text, click) {
                        var b = el('button', '', text);
                        b.addEventListener('click', click);
                        return b;
                    }
                    fetch('$base/secrets/data', {method: 'POST', body: new URLSearchParams({initData: tg.initData, s: q.get('s') || ''})}).then(function (r) {
                        if (!r.ok) {
                            throw r;
                        }
                        return r.json();
                    }).then(function (r) {
                        list.textContent = '';
                        r.items.forEach(function (e) {
                            var item = el('div', 'item', '');
                            item.append(el('div', 'label', e[0]), el('div', 'value', e[1] || '—'));
                            if (e[1] && navigator.clipboard) {
                                item.append(button('copy', function () {
                                    navigator.clipboard.writeText(e[1]);
                                }));
                            }
                            list.append(item);
                        });
                        if (r.warp_profile) {
                            list.append(button('download WARP profile', function () {
                                if (tg.downloadFile) {
                                    tg.downloadFile({url: r.warp_profile, file_name: 'warp.conf'});
                                } else {
                                    location.href = r.warp_profile;
                                }
                            }));
                        }
                    }).catch(function () {
                        list.textContent = 'access denied';
                    });
                </script>
            </body>
            </html>
            HTML;
        break;

    case '/secrets/data':
        header('Content-Type: application/json');
        if ($admin === null) {
            header('403', true, 403);
            echo '{}';
            break;
        }
        $sections = in_array($_POST['s'] ?? '', ['adguard', 'ocserv', 'dnstt', 'warp'], true) ? [$_POST['s']] : ['adguard', 'ocserv', 'dnstt', 'warp'];
        $items    = [];
        foreach ($sections as $sec) {
            foreach ($bot->secretsOf($sec) as $k => $v) {
                $items[] = [$k, $v];
            }
        }
        $profile = null;
        if (in_array('warp', $sections, true) && is_file(BOT_DATA . '/secrets/warp-profile.conf')) {
            // a download link for two minutes, signed with the pool's key
            $exp     = time() + 120;
            $profile = "$base/warp-profile?e=$exp&t=" . hash_hmac('sha256', "warp-profile|$exp", (string) hex2bin((string) ($bot->webSecrets()['initdata_key'] ?? '')));
        }
        echo json_encode(['items' => $items, 'warp_profile' => $profile], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        break;

    // the WARP WireGuard profile: only with a fresh link from /secrets/data
    case '/warp-profile':
        $exp = (int) ($_GET['e'] ?? 0);
        $key = (string) hex2bin((string) ($bot->webSecrets()['initdata_key'] ?? ''));
        $tok = is_string($_GET['t'] ?? null) ? $_GET['t'] : '';
        if ($key === '' || $exp < time() || $exp > time() + 300 || !hash_equals(hash_hmac('sha256', "warp-profile|$exp", $key), $tok)
            || !is_file(BOT_DATA . '/secrets/warp-profile.conf')) {
            header('403', true, 403);
            break;
        }
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="warp.conf"');
        readfile(BOT_DATA . '/secrets/warp-profile.conf');
        break;

    default:
        header('404', true, 404);
}
