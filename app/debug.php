<?php

/*
 * Request log of the web pools while debug is on (/debug, it turns itself
 * off after 30 minutes). Only the shape of a request goes into the log:
 * path hashes, user ids, Telegram sign-in data and form values are masked.
 */

error_reporting(E_ALL);

function debug_mask(string $s): string
{
    $s = preg_replace('~[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}~i', '<uuid>', $s);
    $s = preg_replace('~[0-9a-f]{24,}~i', '<hash>', $s);
    $s = preg_replace('~[A-Za-z0-9_-]{40,}={0,2}~', '<data>', $s);
    return preg_replace('~([?&](?:hash|user|auth_date|query_id|signature|s|id)=)[^&]*~', '$1<masked>', $s);
}

register_shutdown_function(function () {
    $post = array_map(fn($v) => is_string($v) ? strlen($v) . ' bytes' : gettype($v), $_POST);
    error_log('debug: ' . json_encode([
        'method' => $_SERVER['REQUEST_METHOD'] ?? '',
        'uri'    => debug_mask((string) ($_SERVER['REQUEST_URI'] ?? '')),
        'post'   => $post,
        'status' => http_response_code(),
    ], JSON_UNESCAPED_SLASHES));
});
