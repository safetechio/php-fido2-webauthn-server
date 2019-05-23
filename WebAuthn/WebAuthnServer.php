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

    public function beginRegistration()
    {

    }

    public function completeRegistration()
    {

    }

    public function beginAuthentication()
    {

    }

    public function completeAuthentication()
    {

    }
}