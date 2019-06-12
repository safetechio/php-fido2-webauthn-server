<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation;


use SAFETECHio\FIDO2\WebAuthn\Protocol\Client\CollectedClientData;

class ParsedAttestationResponse
{
    /** @var CollectedClientData $CollectedClientData */
    public $CollectedClientData;

    /** @var AttestationObject $AttestationObject */
    public $AttestationObject;
}