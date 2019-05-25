<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation;

use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\AuthenticatorResponse;

class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    /** @var string $AttestationObject */
    public $AttestationObject;

    public function Parse()
    {
        //TODO
    }
}