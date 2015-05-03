<?php

use kuralab\cose\JsonWebToken as JWT;

class JsonWebTokenTest extends PHPUnit_Framework_TestCase
{
  public function testExecute()
  {
    $client_id = 'client123';
    $secret    = 'xxxyyyzzz';
    $nonce     = 'aaabbbccc';

    $jwt1 = new JWT();
    $encodeJwt = $jwt1->encode(
      'HS256',
      'https://example.com',
      $client_id,
      1390318758,
      $nonce,
      $secret
    );

    $jwt2 = new JWT( $encodeJwt );
    $decodedJwt = $jwt2->decode();
    $this->assertEquals( 'JWT', $decodedJwt['header']['typ'] );
    $this->assertEquals( 'HS256', $decodedJwt['header']['alg'] );
    $this->assertEquals( 'https://example.com', $decodedJwt['payload']['iss'] );
    $this->assertEquals( 1390318758, $decodedJwt['payload']['exp'] );
    $this->assertEquals( $nonce, $decodedJwt['payload']['nonce'] );
  }

  /**
   * @expectedException        Exception
   * @expectedExceptionMessage expired iat
   */
  public function testVerifyIat()
  {
    $client_id   = 'client123';
    $secret      = 'xxxyyyzzz';
    $nonce       = 'aaabbbccc';
    $currentTime = 1391247000;

    $stub = $this->getMock(
      '\kuralab\cose\JsonWebToken',
      array( 'getCurrentTime' )
    );
    $stub->expects( $this->any() )
      ->method( 'getCurrentTime' )
      ->will( $this->returnValue( $currentTime ) );

    $encodeJwt = $stub->encode(
      'HS256',
      'https://example.com',
      $client_id,
      time() + 30 * 365 * 24 * 60 * 60,
      $nonce,
      $secret
    );

    $stub2 = $this->getMock(
      '\kuralab\cose\JsonWebToken',
      array( 'getCurrentTime' ),
      array( $encodeJwt )
    );
    $stub2->expects( $this->any() )
      ->method( 'getCurrentTime' )
      ->will( $this->returnValue( $currentTime + 601 ) );

    $stub2->verify(
      'https://example.com',
      $client_id,
      $nonce,
      $secret
    );
  }
}
