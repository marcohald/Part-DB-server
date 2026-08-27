<?php
require 'vendor/autoload.php';
$x = new \ReflectionClass(\Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator::class);
echo "Exists!\n";
