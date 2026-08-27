<?php
require 'vendor/autoload.php';
$x = new \ReflectionClass(\Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge::class);
print_r($x->getMethods());
