<?php
require 'vendor/autoload.php';
$x = new \ReflectionClass(\Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator::class);
print_r($x->getMethods());
