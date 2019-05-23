<?php

namespace SAFETECHio\FIDO2\Tools;

use SAFETECHio\FIDO2\Exceptions\ToolException;

class Tools {

    /**
     * @param string $data
     * @return string
     */
    public static function base64u_encode($data)
    {
        return trim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param string $data
     * @return string
     */
    public static function base64u_decode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * @param $input
     * @param $rawOutput
     * @return string
     */
    public static function SHA256($input, $rawOutput = false)
    {
        return hash('sha256', $input, $rawOutput);
    }

    /**
     * @return string
     * @throws ToolException
     */
    public static function createChallenge()
    {
        $challenge = openssl_random_pseudo_bytes(32, $crypto_strong );
        if( $crypto_strong !== true ) {
            throw new ToolException(
                'Unable to obtain a good source of randomness',
                ToolException::BAD_RANDOM
            );
        }

        $challenge = static::base64u_encode( $challenge );

        return $challenge;
    }
}
