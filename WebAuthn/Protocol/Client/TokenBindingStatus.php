<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Client;


class TokenBindingStatus
{
    const Present = "present";
    const Supported = "supported";
    const NotSupported = "not-supported";

    /**
     * @return array
     * @throws \ReflectionException
     */
    public static function All()
    {
        $tbs = new static;
        $reflectionClass = new \ReflectionClass($tbs);
        return $reflectionClass->getConstants();
    }
}