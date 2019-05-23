<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Entities;

// See (https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity)
class CredentialEntity
{
    /** @var string $Name */
    public $Name;

    /** @var string $Icon*/
	public $Icon;
}