<?php

namespace SAFETECHio\FIDO2\WebAuthn;

use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\WebAuthn\Contracts\User;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\ParsedAttestationResponse;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials\CredentialCreationResponse;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials\ParsedCredentialCreationData;

class WebAuthnCompleteRegistration
{
    /** @var WebAuthnConfig $config */
    protected $config;

    /** @var User $user */
    protected $user;

    /** @var SessionData $sessionData */
    protected $sessionData;

    /** @var string $credentialCreationJSON */
    protected $credentialCreationJSON;

    /**
     * WebAuthnCompleteRegistration constructor.
     * @param User $user
     * @param SessionData $sessionData
     * @param string $credentialCreationJSON
     * @param WebAuthnConfig $config
     * @throws WebAuthnException
     */
    public function __construct(User $user, SessionData $sessionData, string $credentialCreationJSON, WebAuthnConfig $config)
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
        $this->credentialCreationJSON = $credentialCreationJSON;
        $this->config = $config;
    }

    /**
     * @throws WebAuthnException | \Exception
     */
    public function Parse(): ParsedCredentialCreationData
    {
        $credentialCreationResponse = new CredentialCreationResponse($this->credentialCreationJSON);
        return new ParsedCredentialCreationData($credentialCreationResponse);
    }

    /**
     * @param ParsedCredentialCreationData $parsedCredentialCreationData
     * @throws WebAuthnException | \Exception
     */
    public function Verify(ParsedCredentialCreationData $parsedCredentialCreationData)
    {
        $verifyUser = $this->config->AuthenticatorSelection->UserVerification == "required";

        $parsedCredentialCreationData->Verify(
            $this->sessionData->Challenge,
            $verifyUser,
            $this->config->RPID,
            $this->config->RPOrigin
        );
    }
}