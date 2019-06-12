<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation;


use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\AuthenticatorData;

/** See AttestationObject https://www.w3.org/TR/webauthn/#attestation-object */
class AttestationObject
{
    /** @var AuthenticatorData $AuthData */
    public $AuthData;

    /** @var string $RawAuthData */
    public $RawAuthData;

    /** @var string $Format */
    public $Format;

    /** @var array $AttStatement */
    public $AttStatement;
}