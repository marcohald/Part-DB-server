<?php
require 'vendor/autoload.php';
$request = new \Symfony\Component\HttpFoundation\Request([], [], [], [], [], ['HTTP_X_FORWARDED_USER' => 'alice']);
echo $request->headers->get('X-Forwarded-User') . "\n";
echo $request->headers->has('X-FORWARDED-USER') ? "has\n" : "no\n";
echo $request->headers->get('REMOTE_USER') . "\n";
