<?php

namespace SAFETECHio\FIDO2\WebAuthn;

class WebAuthnServer
{
    /** @var WebAuthnConfig */
    protected $config;

    /**
     * WebAuthnServer constructor.
     * @param WebAuthnConfig $config
     */
    public function __construct(WebAuthnConfig $config)
    {
        $this->config = $config;
    }

    public function beginRegistration($user)
    {
        return [];
    }

    public function completeRegistration($user, $sessionData)
    {
        return "";
    }

    public function beginAuthentication($user)
    {
        return [];
    }

    public function completeAuthentication($user, $sessionData)
    {
        return "";
    }
}