<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials;

use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AuthenticatorAttestationResponse;

class CredentialCreationResponse extends PublicKeyCredential
{
    /** @var AuthenticatorAttestationResponse $AttestationResponse */
    public $AttestationResponse;
}