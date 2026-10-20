<?php

function elzw(string $str)
{
    global $text, $load;
    $str = mb_str_split($str);
    $code = 256;
    $r    = $phrase = '';
    $keys = [];
    $last = count($str) - 1;
    $size = count($str);
    $curr = $j = 0;
    $time = microtime(true);
    foreach ($str as $k => $v) {
        $curr ++;
        $percent = (int) ceil($curr * 100 / $size);
        $rotate = $curr != $size ? $load[$j % count($load)] : '';
        $tail = <<<text
                Minified pac $percent% $rotate
                text;
        if (microtime(true) - $time > 0.1) {
            update($text . $tail);
            $time = microtime(true);
            $j++;
        }
        switch (true) {
            case $last == $k:
                $r .= strlen($phrase) > 1 ? mb_chr($keys[$phrase]) : $v;
                break;
            case !empty($keys[$phrase . $str[$k + 1]]):
                $phrase .= $str[$k + 1];
                break;
            default:
                $r .= strlen($phrase) > 1 ? mb_chr($keys[$phrase]) : $v;
                $keys[$phrase . $str[$k + 1]] = $code;
                $code++;
                $phrase = $str[$k + 1];
        }
    }
    return $r;
}

function dlzw($text)
{
    $text = mb_str_split($text);
    $code = 256;
    $r    = $phrase = '';
    $keys = [];
    $last = count($text) - 1;
    foreach ($text as $k => $v) {
        $cc = mb_ord($v);
        $r .= $cc < 256 ? $v : $keys[$cc];
        if ($last == $k) {
            break;
        }
        if (!empty($phrase)) {
            $keys[$code] = $phrase . ($cc < 256 ? $v : $keys[$cc][0]);
            $code++;
        }
        $phrase = $cc < 256 ? $v : $keys[$cc];
    }
    return $r;
}

function getSize($url)
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_HEADER         => 1,
        CURLOPT_NOBODY         => 1,
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_TIMEOUT        => 10,
    ]);
    $r = curl_exec($ch);
    curl_close($ch);
    preg_match('~content-length.+?(\d+)~ius', $r, $m);
    return (int) $m[1];
}

function update($text)
{
    global $bot;
    $bot->update($bot->input['chat'], $bot->input['message_id'], $text);
}

function start()
{
    global $bot, $source, $res, $load, $text;

    $conf = $bot->getPacConf();

    if (!empty($conf['includelist'])) {
        $domains = array_filter($conf['includelist'], fn($x) => $x == true);
        // the PAC file is JavaScript run by clients: only plain domain names
        // get in, whatever an imported list contains
        $domains = array_filter($domains, fn($x, $k) => is_string($k)
            && preg_match('~^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$~iD', $k), ARRAY_FILTER_USE_BOTH);
    }
    if (empty($domains)) {
        $text = "Empty domains. Delete pac files";
        unlink(__DIR__ . '/zapretlists/mpac');
        unlink(__DIR__ . '/zapretlists/pac');
    } else {
        $domains = array_keys($domains);

        $size = count($domains);
        $curr = $j = 0;
        $time = microtime(true);
        $f = fopen(__DIR__ . '/zapretlists/mpac', 'w');
        $t = [];
        foreach ($domains as $v) {
            $curr ++;
            $percent = (int) ceil($curr * 100 / $size);
            $rotate = $curr != $size ? $load[$j % count($load)] : '';
            $tail = <<<text
                    Create pac for shadowsocks-android $percent% $rotate
                    text;
            if (microtime(true) - $time > 0.1) {
                update($text . $tail);
                $time = microtime(true);
                $j++;
            }
            fwrite($f, preg_quote($v) . "\n");

            preg_match('~(.+)\.([^.]+)$~', $v, $m);
            $t[$m[2]][strlen($m[1])][] = $m[1];
        }
        fclose($f);
        $text .= $tail ? "$tail\n" : '';

        // create pac
        $domains = json_encode($t, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $pac     = <<<PAC
                    function FindProxyForURL(t, e) {
                        var n = $domains,
                        r = e.match(/((?:.+\.)*(.+))\.([^.]+)$/);
                        if (r && n.hasOwnProperty(r[3]) && (n[r[3]].hasOwnProperty(r[1].length) && (-1 !== n[r[3]][r[1].length].indexOf(r[1])) || n[r[3]].hasOwnProperty(r[2].length) && (-1 !== n[r[3]][r[2].length].indexOf(r[2])))) {
                            return "SOCKS5 ~address~:~port~; DIRECT";
                        }
                        return "DIRECT";
                    }
                    PAC;
        $pac = preg_replace("~\s{2,}~", '', $pac);
        $pac = preg_replace("~\n~", '', $pac);
        file_put_contents(__DIR__ . '/zapretlists/pac', $pac);
        $text .= "Create minified pac 100%\n";
    }
    // reverse PAC is not built any more, drop files left by older versions
    @unlink(__DIR__ . '/zapretlists/rmpac');
    @unlink(__DIR__ . '/zapretlists/rpac');

    endScript($text);
}

function endScript($text)
{
    global $bot;
    if (empty($_SERVER['argv'][5])) {
        update($text);
        sleep(2);
        $bot->menu('pac');
    }
    die();
}

function download($index)
{
    global $source;
    file_put_contents($source[$index]['dest'], file_get_contents($source[$index]['source']));
}

ini_set('memory_limit', '256M');
require __DIR__ . '/timezone.php';
// require __DIR__ . '/debug.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';
$source = [
    [
        'source' => 'https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt',
        'dest'   => __DIR__ . '/zapretlists/nxdomain.txt',
    ],
    [
        'source' => 'https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv',
        'dest'   => __DIR__ . '/zapretlists/dump.csv',
    ],
];

$res = __DIR__ . '/zapretlists/result';

$text = '';
$load = [
    '/',
    '-',
    '\\',
];
switch ($_SERVER['argv'][1]) {
    case 'start':
        $bot                       = new Bot($c['key'], $i);
        $bot->input['chat']        = $_SERVER['argv'][2];
        $bot->input['message_id']  = $_SERVER['argv'][3];
        $bot->input['callback_id'] = $_SERVER['argv'][4];
        start();
        break;
    case 'download':
        download($_SERVER['argv'][2]);
        break;
}
