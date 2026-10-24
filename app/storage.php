<?php

/*
 * The bot's working state lives in /data (./data on the host). It is not
 * tracked by git, so an update cannot reset it; the files in /config are
 * templates only. Files are replaced atomically (temporary file + rename)
 * under flock: a reader never sees half a file, two writers (the bot in
 * php, the cron loop in service) do not mix their changes.
 */

const BOT_DATA = '/data';

// groups of the web pools (dockerfile/php.dockerfile): botweb serves the
// public endpoints (subscriptions), botadmin the Mini App and is also in
// botsecret, the group of /data/secrets
const BOT_GID_WEB    = 10080;
const BOT_GID_SECRET = 10082;

/**
 * Runs $fn under an exclusive lock that belongs to $path (a .lock file
 * next to it). Re-entrant within one process: a nested call for the same
 * path does not wait for itself.
 */
function bot_lock(string $path, callable $fn)
{
    static $held = [];
    $lock = dirname($path) . '/.' . basename($path) . '.lock';
    if (!empty($held[$lock])) {
        return $fn();
    }
    $l = @fopen($lock, 'c');
    if ($l === false) {
        throw new RuntimeException("cannot open the lock $lock");
    }
    if (!flock($l, LOCK_EX)) {
        fclose($l);
        throw new RuntimeException("cannot lock $lock");
    }
    $held[$lock] = true;
    try {
        return $fn();
    } finally {
        unset($held[$lock]);
        flock($l, LOCK_UN);
        fclose($l);
    }
}

/**
 * Replaces $path with $data: written to a temporary file in the same
 * folder, flushed to disk, then renamed over $path. $gid: group of the
 * file (a web pool that has to read it).
 */
function bot_write(string $path, string $data, int $mode = 0600, ?int $gid = null): void
{
    bot_lock($path, function () use ($path, $data, $mode, $gid) {
        $tmp = dirname($path) . '/.' . basename($path) . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $f   = @fopen($tmp, 'x');
        if ($f === false) {
            throw new RuntimeException("cannot write $tmp");
        }
        $ok = fwrite($f, $data) === strlen($data) && fflush($f) && fsync($f);
        fclose($f);
        if ($ok) {
            @chmod($tmp, $mode);
            if ($gid !== null) {
                @chgrp($tmp, $gid);
            }
            $ok = rename($tmp, $path);
        }
        if (!$ok) {
            @unlink($tmp);
            throw new RuntimeException("cannot write $path");
        }
    });
}

// the file's content; an exception if it cannot be read (never a default)
function bot_read(string $path): string
{
    $s = @file_get_contents($path);
    if ($s === false) {
        throw new RuntimeException("cannot read $path");
    }
    return $s;
}

// a JSON object/array file; an exception if it is missing or damaged
function bot_read_json(string $path): array
{
    $j = json_decode(bot_read($path), true);
    if (!is_array($j)) {
        throw new RuntimeException("damaged JSON in $path");
    }
    return $j;
}

function bot_write_json(string $path, array $data, int $mode = 0600, ?int $gid = null, int $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES): void
{
    $json = json_encode($data ?: new stdClass(), $flags);
    if ($json === false) {
        throw new RuntimeException("cannot encode $path: " . json_last_error_msg());
    }
    bot_write($path, $json, $mode, $gid);
}

/**
 * Read-modify-write of a JSON file under its lock: $fn gets the current
 * content and returns the new one.
 */
function bot_update_json(string $path, callable $fn, int $mode = 0600, ?int $gid = null, bool $missingOk = false): array
{
    return bot_lock($path, function () use ($path, $fn, $mode, $gid, $missingOk) {
        $cur = $missingOk && !file_exists($path) ? [] : bot_read_json($path);
        $new = $fn($cur);
        bot_write_json($path, $new, $mode, $gid);
        return $new;
    });
}

/**
 * The bot's own config: token, admins ($c). An exception if the file is
 * missing, empty or damaged: then nobody must become admin and nothing
 * must be written over it.
 */
function bot_config(): array
{
    $file = BOT_DATA . '/config.php';
    if (function_exists('opcache_invalidate')) {
        @opcache_invalidate($file, true);
    }
    clearstatcache(true, $file);
    if (!is_file($file) || !is_readable($file) || filesize($file) === 0) {
        throw new RuntimeException("cannot read $file");
    }
    $c = null;
    include $file;
    if (!is_array($c) || empty($c['key']) || !is_string($c['key'])) {
        throw new RuntimeException("damaged $file: no bot key");
    }
    return $c;
}

function bot_config_save(array $c): void
{
    if (empty($c['key'])) {
        throw new RuntimeException('config without the bot key is not saved');
    }
    $file = BOT_DATA . '/config.php';
    bot_write($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n", 0600);
    if (function_exists('opcache_invalidate')) {
        @opcache_invalidate($file, true);
    }
}

/**
 * Before the bot starts: the folders and, for whatever the migration
 * (scripts/migrate_data.sh) did not bring, the templates from /config.
 * Only missing files are written, never over existing ones.
 */
function bot_prepare_files(): void
{
    foreach (['', '/xray', '/adguard', '/ocserv', '/up', '/ng', '/www', '/dnstt'] as $d) {
        if (!is_dir(BOT_DATA . $d) && !@mkdir(BOT_DATA . $d, 0700, true)) {
            throw new RuntimeException('cannot create ' . BOT_DATA . $d);
        }
    }
    foreach ([
        'pac.json'                 => 'pac.json',
        'xray/xray.json'           => 'xray.json',
        'adguard/AdGuardHome.yaml' => 'AdGuardHome.yaml',
        'ocserv/ocserv.conf'       => 'ocserv.conf',
        'ocserv/ocserv.passwd'     => 'ocserv.passwd',
        'up/upstream.conf'         => 'upstream.conf',
        'up/deny'                  => 'deny',
    ] as $to => $from) {
        if (!file_exists(BOT_DATA . "/$to")) {
            bot_write(BOT_DATA . "/$to", bot_read("/config/$from"));
        }
    }
}
