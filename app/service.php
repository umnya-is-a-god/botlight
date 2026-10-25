<?php

require __DIR__ . '/timezone.php';

require __DIR__ . '/bot.php';
require __DIR__ . '/storage.php';
$c = bot_config();
require __DIR__ . '/i18n.php';


$bot = new Bot($c['key'], $i);

// each step on its own: one failing step must not stop the others
// (or the start message and the menu)
$steps = [
    'selfUpdate'     => fn() => $bot->selfUpdate(),
    'sslip'          => function () use ($bot) {
        $bot->dontshowcron = 1;
        $bot->sslip();
    },
    'adguardSync'    => fn() => $bot->adguardSync(),
    'cloakNginx'     => fn() => $bot->cloakNginx(),
    'syncDeny'       => fn() => $bot->syncDeny(),
    'dnsttStart'     => fn() => $bot->dnsttStart(),
    'upstream'       => function () use ($bot) {
        $c = $bot->getPacConf();
        $bot->setUpstreamDomain(($c['transport'] ?? '') != 'Reality' ? 't' : ($c['reality']['domain'] ?? ''));
        $bot->setUpstreamDomainOcserv($c['domain'] ?? '');
    },
    'xrayUpdateRules' => fn() => $bot->xrayUpdateRules(),
];
foreach ($steps as $name => $step) {
    try {
        $step();
    } catch (Throwable $e) {
        error_log("service.php $name: $e");
    }
}
