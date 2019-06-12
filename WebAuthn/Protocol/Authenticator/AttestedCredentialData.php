<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;


class AttestedCredentialData
{
    /** @var string $AAGUID */
    public $AAGUID;

    /** @var string $CredentialID */
    public $CredentialID;

    /** @var string $CredentialPublicKey */
    public $CredentialPublicKey;
}