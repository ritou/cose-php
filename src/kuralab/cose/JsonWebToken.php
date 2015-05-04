<?php
namespace kuralab\cose;

use CBOR\CBOREncoder;

/**
 * Json Web Token Class
 */
class JsonWebToken
{
    // TBD
    private static $supportedAlgorithm = array(
        'HS256' => 'sha256',
        'HS382' => 'sha384',
        'HS512' => 'sha512',
        'RS256' => 'sha256',
        'RS382' => 'sha384',
        'RS512' => 'sha512',
    );

    private $signature;

    private $headerArray  = array();
    private $payloadArray = array();

    public function __construct($idToken = null)
    {
        if (!is_null($idToken)) {
            $decodedIdToken = CBOREncoder::decode($idToken);
            if (count($decodedIdToken) == 3) {
                $this->headerArray  = $decodedIdToken[0];
                $this->payloadArray = $decodedIdToken[1];
                $this->signature    = $decodedIdToken[2];
            }
        }
    }

    public function encode($algorithm, $issuer, $audience, $expiration, $nonce, $secret)
    {
        if (!array_key_exists($algorithm, self::$supportedAlgorithm)) {
            throw new \Exception('unsupported algorithm');
        }
        $headerArray = array(
            'alg' => $algorithm,
            'typ' => 'JWT'
        );
        $payloadArray = array(
            'iss'   => $issuer,
            'aud'   => $audience,
            'exp'   => $expiration,
            'iat'   => $this->getCurrentTime(),
            'nonce' => $nonce
        );
        $header  = $headerArray;
        $payload = $payloadArray;
        $signature = $this->generateSignature(
            $header,
            $payload,
            $algorithm,
            $secret
        );

        return CBOREncoder::encode(array( $header, $payload, $signature ));
    }

    public function decode()
    {
        if (is_null($this->headerArray) ||
            is_null($this->payloadArray) || is_null($this->signature)) {
            return null;
        }
        $result = array(
            'header'    => $this->headerArray,
            'payload'   => $this->payloadArray,
            'signature' => $this->signature,
        );
        return $result;
    }

    public function getHeader($key = null)
    {
        if (is_string($key) && array_key_exists($key, $this->headerArray)) {
            return $this->headerArray[$key];
        }
        return $this->headerArray;
    }

    public function getPayload($key = null)
    {
        if (is_string($key) && array_key_exists($key, $this->payloadArray)) {
            return $this->payloadArray[$key];
        }
        return $this->payloadArray;
    }

    public function verify($issuer, $audience, $nonce, $secret, $iatLimit = 600)
    {
        /**
         * check header
         */
        if ($this->headerArray['typ'] != 'JWT') {
            throw new \Exception('unexpected type');
        }

        if ($this->headerArray['alg'] == null) {
            throw new \Exception('algorithm is null');
        }

        /**
         * check payload
         */
        // iss
        if ($this->payloadArray['iss'] != $issuer) {
            throw new \Exception('invalid iss');
        }

        // aud
        if ($this->payloadArray['aud'] != $audience) {
            throw new \Exception('invalid aud');
        }

        // exp
        if ($this->payloadArray['exp'] < $this->getCurrentTime()) {
            throw new \Exception('expired id token');
        }

        // iat
        if ($this->getCurrentTime() - $this->payloadArray['iat'] > $iatLimit) {
            throw new \Exception('expired iat');
        }

        // nonce
        if ($this->payloadArray['nonce'] != $nonce) {
            throw new \Exception('invalid nonce');
        }

        /**
         * check signature
         */
        if (preg_match('/^HS/', $this->headerArray['alg'])) {
            $sig = $this->generateSignature(
                $this->headerArray,
                $this->payloadArray,
                $this->headerArray['alg'],
                $secret
            );
            if ($this->signature != $sig) {
                throw new \Exception('signature error');
            }
        } elseif (preg_match('/^RS/', $this->headerArray['alg'])) {
            $publicKey = openssl_pkey_get_public($secret);
            $result = openssl_verify(
                CBOREncoder::encode(array( $this->headerArray, $this->payloadArray )),
                $this->decodeUulSafe($signature),
                $publicKey,
                self::$supportedAlgorithm[$this->headerArray['alg']]
            );

            if ($result != 1) {
                throw new \Exception('signature error');
            }
        } else {
            throw new \Exception('unsupported algorithm');
        }
    }

    private function generateSignature($header, $payload, $algorithm, $secret)
    {
        if (!array_key_exists($algorithm, self::$supportedAlgorithm)) {
            throw new \Exception('unsupported algorithm');
        }

        if (preg_match('/^HS/', $algorithm)) {
            $signature = hash_hmac(
                self::$supportedAlgorithm[$algorithm],
                CBOREncoder::encode(array( $header, $payload )),
                $secret,
                true
            );
        } elseif (preg_match('/^RS/', $algorithm)) {
            $signature = $this->encryptRsa(
                self::$supportedAlgorithm[$algorithm],
                CBOREncoder::encode(array( $header, $payload )),
                $secret
            );
        } else {
            throw new \Exception('unsupported algorithm');
        }

        return $signature;
    }

    private function encryptRsa($algorithm, $data, $secret)
    {
        $privateKeyId = openssl_pkey_get_private($secret);
        openssl_sign($data, $signature, $privateKeyId, $algorithm);
        openssl_free_key($privateKeyId);

        return $signature;
    }

    public function getCurrentTime()
    {
        return time();
    }

    public function decodeUrlSafe($data)
    {
        $data = str_replace(array('-', '_'), array('+', '/'), $data);

        $lack = strlen($data) % 4;
        if ($lack > 0) {
            $padding = 4 - $lack;
            $data .= str_repeat('=', $padding);
        }
        return base64_decode($data);
    }
}
