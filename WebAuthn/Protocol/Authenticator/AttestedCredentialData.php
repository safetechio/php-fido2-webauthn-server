<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;

/** See https://www.w3.org/TR/webauthn/#attested-credential-data */
class AttestedCredentialData
{
    /** @var string $AAGUID */
    public $AAGUID;

    /** @var string $CredentialID */
    public $CredentialID;

    /** @var string $CredentialPublicKey */
    public $CredentialPublicKey;
}