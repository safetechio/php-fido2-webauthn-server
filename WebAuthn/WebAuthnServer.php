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
     * @return Credential
     * @throws WebAuthnException
     */
    public function completeRegistration(User $user, SessionData $sessionData, string $credentialCreationResponse): Credential
    {
        $completeReg = new WebAuthnCompleteRegistration($user, $sessionData, $credentialCreationResponse, $this->config);
        $pccd = $completeReg->Parse();
        $completeReg->Verify($pccd);

       return new Credential(
            $pccd->Response->AttestationObject->AuthData->AttData->CredentialID,
            $pccd->Response->AttestationObject->AuthData->AttData->CredentialPublicKey,
            $pccd->Response->AttestationObject->Format,
            new Authenticator(
                $pccd->Response->AttestationObject->AuthData->AttData->AAGUID,
                $pccd->Response->AttestationObject->AuthData->Counter
            )
        );
    }

    /**
     * @param User $user
     * @return WebAuthnBeginAuthentication
     * @throws ToolException
     * @throws WebAuthnException
     */
    public function beginAuthentication(User $user)
    {
        return new WebAuthnBeginAuthentication($user, $this->config);
    }

    /**
     * @param User $user
     * @param SessionData $sessionData
     * @param string $credentialAssertionResponse
     * @throws WebAuthnException
     * @throws \ReflectionException
     */
    public function completeAuthentication(User $user, SessionData $sessionData, string $credentialAssertionResponse)
    {
        $completeAuth = new WebAuthnCompleteAuthentication($user, $sessionData, $credentialAssertionResponse, $this->config);
        $pcad = $completeAuth->Parse();
        $completeAuth->Verify($pcad);
    }
}