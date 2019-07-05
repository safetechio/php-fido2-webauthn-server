<?php

namespace SAFETECHio\FIDO2\WebAuthn;


use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\WebAuthn\Contracts\User;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Assertion\CredentialAssertionResponse;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Assertion\ParsedCredentialAssertionData;

class WebAuthnCompleteAuthentication
{
    /** @var WebAuthnConfig $config */
    protected $config;

    /** @var User $user */
    protected $user;

    /** @var SessionData $sessionData */
    protected $sessionData;

    /** @var string $credentialAssertionJSON */
    protected $credentialAssertionJSON;

    /**
     * WebAuthnCompleteRegistration constructor.
     * @param User $user
     * @param SessionData $sessionData
     * @param string $credentialAssertionJSON
     * @param WebAuthnConfig $config
     * @throws WebAuthnException
     */
    public function __construct(User $user, SessionData $sessionData, string $credentialAssertionJSON, WebAuthnConfig $config)
    {
        // TODO move to validation function
        // Check that the user ID and session userId Match
        if($user->WebAuthnID() != $sessionData->UserID){
            throw new WebAuthnException(
                "ID Mismatch: User ID and session's User ID do not match",
                WebAuthnException::ID_MISMATCH
            );
        }
        // TODO validate config has $config->AuthenticatorSelection->UserVerification set

        $this->user = $user;
        $this->sessionData = $sessionData;
        $this->credentialAssertionJSON = $credentialAssertionJSON;
        $this->config = $config;
    }

    /**
     * @throws WebAuthnException
     */
    public function Parse()
    {
        $credentialAssertionResponse = new CredentialAssertionResponse($this->credentialAssertionJSON);
        return new ParsedCredentialAssertionData($credentialAssertionResponse);
    }

    /**
     * @param ParsedCredentialAssertionData $parsedCredentialCreationData
     * @throws WebAuthnException
     * @throws \ReflectionException
     */
    public function Verify(ParsedCredentialAssertionData $parsedCredentialCreationData)
    {
        $verifyUser = $this->config->AuthenticatorSelection->UserVerification == "required";

        // Find the matching User Credential
        foreach ($this->user->WebAuthnCredentials() as $credential){
            if($credential->ID == $parsedCredentialCreationData->RawID){
                $authenticationCredential = $credential;
            }
        }

        if(!isset($authenticationCredential)){
            throw new WebAuthnException(
                "User has no matching credentials.",
                WebAuthnException::USER_NO_CREDENTIALS_FOUND
            );
        }

        $parsedCredentialCreationData->Verify(
            $this->sessionData->Challenge,
            $verifyUser,
            $this->config->RPID,
            $this->config->RPOrigin,
            $authenticationCredential->PublicKey
        );
    }

}