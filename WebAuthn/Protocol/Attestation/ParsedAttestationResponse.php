<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation;

use SAFETECHio\FIDO2\WebAuthn\Protocol\Client\CollectedClientData;

class ParsedAttestationResponse
{
    /** @var CollectedClientData $CollectedClientData */
    public $CollectedClientData;

    /** @var AttestationObject $AttestationObject */
    public $AttestationObject;

    /**
     * ParsedAttestationResponse constructor.
     * @param AuthenticatorAttestationResponse $authenticatorAttestationResponse
     * @throws \Exception
     */
    public function __construct(AuthenticatorAttestationResponse $authenticatorAttestationResponse)
    {
        $this->CollectedClientData = new CollectedClientData($authenticatorAttestationResponse->ClientDataJSON);
        $this->AttestationObject = new AttestationObject($authenticatorAttestationResponse->AttestationObject);
    }
}