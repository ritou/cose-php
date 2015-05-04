<?php
require_once("src/kuralab/cose/JsonWebToken.php");
require_once("vendor/autoload.php");

use kuralab\cose\JsonWebToken as JWT;

// initialize parameters
$algorithm  = 'HS256';
$audience   = 'https://example.com';
$clientId   = 'YOUR_CLIENT_ID';
$secret     = 'YOUR_SECRET';
$expiration = time() + 30 * 24 * 60 * 60; // 30 days
$nonce      = 'abc123';

// encode jwt
$jwtObj = new JWT();
$encodedJwt = $jwtObj->encode(
    $algorithm,
    $audience,
    $clientId,
    $expiration,
    $nonce,
    $secret
);
echo "=== Encoded Json Web Token ===\n";
$byteArr = unpack("C*", $encodedJwt);
echo "Byte dec map = " . implode(" ", $byteArr) . PHP_EOL;
echo "\n";
echo "Byte hex map = " . implode(" ", array_map(function ($byte) {
    return "0x" . strtoupper(dechex($byte));
}, $byteArr)) . PHP_EOL;
echo "\n\n";

try {
    // verify and decode jwt
    $jwtObj = new JWT($encodedJwt);
    $jwtObj->verify(
        $audience,
        $clientId,
        $nonce,
        $secret
    );
    $decodedJwt = $jwtObj->decode();
    echo "=== Decoded Json Web Token ===\n";
    print_r($decodedJwt);
} catch (Exception $e) {
    var_dump($e);
}
