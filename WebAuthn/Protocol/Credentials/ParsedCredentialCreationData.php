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
     * ParsedCredentialCreationData constructor.
     * @param CredentialCreationResponse $credentialCreationResponse
     * @throws \Exception
     */
    public function __construct(CredentialCreationResponse $credentialCreationResponse)
    {
        $this->Raw = $credentialCreationResponse;
        $this->ID = $credentialCreationResponse->ID;
        $this->RawID = $credentialCreationResponse->RawID;
        $this->Type = $credentialCreationResponse->Type;
        $this->Response = new ParsedAttestationResponse($credentialCreationResponse->AttestationResponse);
    }

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
        // TODO
    }
}