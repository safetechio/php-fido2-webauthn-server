<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials;


use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\ParsedAttestationResponse;

class ParsedCredentialCreationData extends ParsedPublicKeyCredential
{
    /** @var ParsedAttestationResponse $Response */
    public $Response;

    /** @var CredentialCreationResponse $Raw */
    public $Raw;

    /**
     * See https://www.w3.org/TR/webauthn/#registering-a-new-credential
     *
     * @param string $challenge
     * @param bool $verifyUser
     * @param string $relyingPartyID
     * @param string $relyingPartyOrigin
     */
    public function Verify(string $challenge, bool $verifyUser, string $relyingPartyID, string $relyingPartyOrigin)
    {

    }
}