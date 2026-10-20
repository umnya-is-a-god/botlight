<?php

require __DIR__ . '/timezone.php';

require __DIR__ . '/bot.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';

if ($c['debug']) {
    require __DIR__ . '/debug.php';
}

$bot = new Bot($c['key'], $i);

$bot->selfUpdate();
$bot->dontshowcron = 1;
$bot->sslip();
$bot->adguardSync();
$bot->cloakNginx();
$bot->syncDeny();
$bot->cleanDocker();
$bot->dnsttStart();
$c = $bot->getPacConf();
$bot->setUpstreamDomain($c['transport'] != 'Reality' ? 't' : $c['reality']['domain']);
$bot->setUpstreamDomainOcserv($c['domain']);
$bot->xrayUpdateRules();
