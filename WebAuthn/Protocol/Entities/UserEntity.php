<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Entities;

// See (https://www.w3.org/TR/webauthn/#sctn-user-credential-params)
class UserEntity extends CredentialEntity
{
    /** @var string $DisplayName */
    public $DisplayName;

    /** @var string $ID */
    public $ID;
}