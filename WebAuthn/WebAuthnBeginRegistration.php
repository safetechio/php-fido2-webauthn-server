<?php

namespace SAFETECHio\FIDO2\WebAuthn;

use SAFETECHio\FIDO2\Exceptions\ToolException;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Contracts\User;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\UserVerificationRequirement;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Entities\RelyingPartyEntity;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Entities\UserEntity;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\AuthenticationExtensionsClientInputs;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\AuthenticatorSelection;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\ConveyancePreference;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\CredentialCreation;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\CredentialDescriptor;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\CredentialParameter;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\PublicKeyCredentialCreationOptions;

class WebAuthnBeginRegistration
{
    /** @var WebAuthnConfig */
    protected $config;

    /** @var User $user */
    protected $user;

    /** @var PublicKeyCredentialCreationOptions $creationOptions */
    protected $creationOptions;

    /**
     * WebAuthnBeginRegistration constructor.
     * @param $user
     * @param $config
     * @throws ToolException
     */
    public function __construct(User $user, WebAuthnConfig $config)
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

        $this->creationOptions = $creationOptions;
    }

    /**
     * @return array
     */
    public function Make()
    {
        $response = new CredentialCreation($this->creationOptions);

	    $newSessionData = new SessionData;
        $newSessionData->Challenge = Tools::base64u_encode($this->creationOptions->Challenge);
		$newSessionData->UserID = $this->user->WebAuthnID();

		return [$response, $newSessionData];
    }

    /**
     * @param AuthenticatorSelection $authenticatorSelection
     * @return WebAuthnBeginRegistration
     */
    public function WithAuthenticatorSelection(AuthenticatorSelection $authenticatorSelection)
    {
        $this->creationOptions->AuthenticatorSelection = $authenticatorSelection;
        return $this;
    }

    /**
     * @param CredentialDescriptor[] $excludeList
     * @return WebAuthnBeginRegistration $this
     */
    public function WithExclusions(array $excludeList)
    {
        $this->creationOptions->CredentialExcludeList = $excludeList;
        return $this;
    }

    /**
     * @param ConveyancePreference $preference
     * @return WebAuthnBeginRegistration $this
     */
    public function WithConveyancePreference(ConveyancePreference $preference)
    {
        $this->creationOptions->Attestation = $preference;
        return $this;
    }

    /**
     * @param AuthenticationExtensionsClientInputs $preference
     * @return WebAuthnBeginRegistration$this
     */
    public function WithExtensions(AuthenticationExtensionsClientInputs $preference)
    {
        $this->creationOptions->Extensions = $preference;
        return $this;
    }
}