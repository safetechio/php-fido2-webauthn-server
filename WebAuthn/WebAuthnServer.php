<?php

namespace SAFETECHio\FIDO2\WebAuthn;

use SAFETECHio\FIDO2\Exceptions\ToolException;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
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

    /**
     * @param User $user
     * @param SessionData $sessionData
     * @param string $credentialCreationResponse
     * @return string
     * @throws WebAuthnException
     */
    public function completeRegistration(User $user, SessionData $sessionData, string $credentialCreationResponse)
    {
        new WebAuthnCompleteRegistration($user, $sessionData, $credentialCreationResponse);

        return "";
    }

    public function beginAuthentication(User $user)
    {
        return [];
    }

    public function completeAuthentication(User $user, SessionData $sessionData)
    {
        return "";
    }
}