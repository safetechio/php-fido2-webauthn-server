<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation;

use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\AuthenticatorResponse;

class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    /** @var string $AttestationObject */
    public $AttestationObject;

    public function __construct(array $response)
    {
        $this->AttestationObject = $response["attestationObject"];
        $this->ClientDataJSON = $response["clientDataJSON"];
    }
}