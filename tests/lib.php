<?php

// A few asserts for the tests in this folder (php tests/<name>.php): the
// count of failures is the exit code.

$GLOBALS['failed'] = 0;

function check(string $what, bool $ok): void
{
    echo ($ok ? 'ok   ' : 'FAIL ') . $what . "\n";
    if (!$ok) {
        $GLOBALS['failed']++;
    }
}

function done(): void
{
    echo $GLOBALS['failed'] ? "{$GLOBALS['failed']} failed\n" : "all passed\n";
    exit(min(255, $GLOBALS['failed']));
}
