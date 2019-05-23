<?php

namespace SAFETECHio\FIDO2\WebAuthn;

use SAFETECHio\FIDO2\Exceptions\ToolException;
use SAFETECHio\FIDO2\WebAuthn\Contracts\User;

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

    /**
     * @param User $user
     * @return WebAuthnBeginRegistration
     * @throws ToolException
     */
    public function BeginRegistration(User $user)
    {
        return new WebAuthnBeginRegistration($user, $this->config);
    }

    public function completeRegistration(User $user, $sessionData)
    {
        return "";
    }

    public function beginAuthentication(User $user)
    {
        return [];
    }

    public function completeAuthentication(User $user, $sessionData)
    {
        return "";
    }
}