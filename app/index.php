<?php

require __DIR__ . '/timezone.php';
require __DIR__ . '/config.php';
if ($c['debug']) {
    require __DIR__ . '/debug.php';
}
require __DIR__ . '/calc.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/i18n.php';
if (file_exists(__DIR__ . '/override.php')) {
    include __DIR__ . '/override.php';
}
$bot  = new Bot($c['key'], $i);
$hash = $bot->getHashBot();

// Telegram Mini App initData check: valid signature, issued for an admin,
// not older than a day. Anything that changes or reveals bot settings
// requires it; the path hash alone is known to every subscriber.
$webapp = false;
if (!empty($_GET['hash']) && is_string($_GET['hash'])) {
    $t = $_GET;
    unset($t['hash']);
    ksort($t);
    $s = [];
    foreach ($t as $k => $v) {
        if (!is_string($v)) {
            $s = false;
            break;
        }
        $s[] = "$k=$v";
    }
    if ($s !== false) {
        $sk   = hash_hmac('sha256', $c['key'], 'WebAppData', true);
        $user = json_decode($_GET['user'] ?? '', true);
        $webapp = hash_equals(hash_hmac('sha256', implode("\n", $s), $sk), $_GET['hash'])
            && (time() - (int) ($_GET['auth_date'] ?? 0)) < 86400
            && !empty($user['id'])
            && in_array($user['id'], (array) ($c['admin'] ?? []));
    }
}
$templateTypes = ['sing', 'clash'];

switch (true) {
    // save template (webapp editor)
    case preg_match('~^' . preg_quote("/webapp$hash/save") . '~', $_SERVER['REQUEST_URI']) && $webapp && !empty($_POST['json']):
        if (!in_array($_POST['type'] ?? '', $templateTypes, true) || !is_string($_POST['name'] ?? null) || $_POST['name'] === '') {
            echo json_encode(['status' => false, 'message' => 'wrong template']);
            break;
        }
        echo json_encode($bot->saveTemplate($_POST['name'], $_POST['type'], $_POST['json']));
        break;

    // load template (webapp editor)
    case preg_match('~^' . preg_quote("/webapp$hash/load") . '~', $_SERVER['REQUEST_URI']) && $webapp:
        $ty = $_POST['type'] ?? '';
        $te = $_POST['name'] ?? '';
        if (!in_array($ty, $templateTypes, true) || !is_string($te)) {
            header('400', true, 400);
            break;
        }
        $t = $te !== '' && $te !== 'origin'
            ? ($bot->getPacConf()["{$ty}templates"][$te] ?? null)
            : json_decode(file_get_contents("/config/$ty.json"), true);
        header('Content-Type: application/json');
        echo json_encode($t ?? new stdClass(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        break;

    // adguard cookie
    case preg_match('~^' . preg_quote("/webapp$hash/check") . '~', $_SERVER['REQUEST_URI']) && $webapp:
        setcookie('c', $bot->getAdguardCookie(), 0, '/', '', true, true);
        echo "/adguard$hash/";
        break;

    case preg_match('~^' . preg_quote("/pac$hash/sub") . '~', $_SERVER['REQUEST_URI']) && file_exists(__DIR__ . '/subscription.php'):
        $bot->sub();
        exit;

    // subs & pac
    case preg_match('~^' . preg_quote("/pac$hash") . '~', $_SERVER['REQUEST_URI']):
        // sing-box import links carry their parameters in the path
        $part = explode('/', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH))[2] ?? '';
        if ($part !== '' && is_array($t = @unserialize(base64_decode($part, true), ['allowed_classes' => false]))) {
            foreach (['h', 't', 's', 'r'] as $k) {
                if (isset($t[$k]) && is_scalar($t[$k])) {
                    $_GET[$k] = (string) $t[$k];
                }
            }
        }
        $type    = is_string($_GET['t'] ?? null) ? $_GET['t'] : 'pac';
        $address = preg_match('~^[A-Za-z0-9.:\[\]-]{1,253}$~', $_GET['a'] ?? '') ? $_GET['a'] : '127.0.0.1';
        $port    = preg_match('~^\d{1,5}$~', $_GET['p'] ?? '') ? $_GET['p'] : '1080';
        switch ($type) {
            case 's':
            case 'si':
            case 'cl':
                $bot->subscription();
                exit;

            case 'te':
                $ty = $_GET['ty'] ?? '';
                $te = is_string($_GET['te'] ?? null) ? $_GET['te'] : '';
                if (!in_array($ty, $templateTypes, true)) {
                    header('404', true, 404);
                    exit;
                }
                header('Content-Type: text/html');
                $js   = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE;
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
                        <link href="/webapp$hash/jsoneditor.min.css" rel="stylesheet" type="text/css">
                        <script src="/webapp$hash/jsoneditor.min.js"></script>
                        <script src="/webapp$hash/jquery-3.7.1.min.js"></script>
                        <script src="https://telegram.org/js/telegram-web-app.js"></script>
                    </head>
                    <body style="height:100%">
                        <div id="jsoneditor" style="height:100%"></div>
                        <script>
                            jQuery(function($) {
                                var tg = window.Telegram.WebApp;
                                var name = $name, type = $tyjs;
                                const editor = new JSONEditor(document.getElementById("jsoneditor"), {});
                                // the template is only sent to an admin's signed Telegram session
                                $.ajax({
                                    url: '/webapp$hash/load?' + tg.initData,
                                    method: 'POST',
                                    data: {name: name, type: type},
                                    dataType: 'json'
                                }).done(function (t) {
                                    editor.set(t);
                                }).fail(function () {
                                    document.getElementById("jsoneditor").textContent = 'access denied';
                                });
                                tg.MainButton.show().setText($save).onClick(function () {
                                    $.ajax({
                                        url: '/webapp$hash/save?' + tg.initData,
                                        method: 'POST',
                                        data: {name: name, type: type, json: editor.getText()},
                                        dataType: 'json'
                                    }).done(function (r) {
                                        if (r.status == true) {
                                            tg.MainButton.setText($ok);
                                            setTimeout(() => { tg.close(); }, 500);
                                        } else {
                                            tg.MainButton.setText(r.message);
                                        }
                                    }).fail(function () {
                                        tg.MainButton.setText($err);
                                    });
                                });
                            });
                        </script>
                    </body>
                    </html>
                    HTML;
                exit;

            default:
                // only the generated PAC files; $type must never become a path
                if (in_array($type, ['pac', 'mpac'], true) && file_exists($file = __DIR__ . "/zapretlists/$type")) {
                    $pac = file_get_contents($file);
                    header('Content-Type: text/plain');
                    echo str_replace([
                        '~address~',
                        '~port~',
                    ], [
                        $address,
                        $port,
                    ], $pac);
                    exit;
                }
                break;
        }
        break;

    default:
        header('500', true, 500);
}
