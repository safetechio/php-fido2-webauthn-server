<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Entities;

// See (https://www.w3.org/TR/webauthn/#sctn-rp-credential-params)
class RelyingPartyEntity extends CredentialEntity
{
    /** @var string $ID */
    public $ID;
}