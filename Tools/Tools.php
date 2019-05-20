<?php

namespace SAFETECHio\FIDO2\Tools;

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
}
