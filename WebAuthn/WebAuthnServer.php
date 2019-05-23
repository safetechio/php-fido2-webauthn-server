<?php

namespace SAFETECHio\FIDO2\WebAuthn;

use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Contracts\User;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\UserVerificationRequirement;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Entities\RelyingPartyEntity;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Entities\UserEntity;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\AuthenticatorSelection;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\ConveyancePreference;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\CredentialParameter;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\PublicKeyCredentialCreationOptions;

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
     * @param $user
     * @return array
     * @throws \SAFETECHio\FIDO2\Exceptions\ToolException
     */
    public function beginRegistration(User $user)
    {
        $challenge = Tools::createChallenge();

        $webAuthnUser = UserEntity::FromUser($user);

        $relyingParty = RelyingPartyEntity::FromConfig($this->config);

        $credentialParams = CredentialParameter::all();

        $authSelection = new AuthenticatorSelection(
            false,
            UserVerificationRequirement::VerificationPreferred
        );

        $creationOptions = new PublicKeyCredentialCreationOptions();
        $creationOptions->Challenge = $challenge;
        $creationOptions->RelyingParty = $relyingParty;
        $creationOptions->User = $webAuthnUser;
        $creationOptions->Parameters = $credentialParams;
        $creationOptions->AuthenticatorSelection = $authSelection;
        $creationOptions->Timeout = $this->config->Timeout;
        $creationOptions->Attestation = ConveyancePreference::PreferDirectAttestation; // The Default is `none`

        return [];
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