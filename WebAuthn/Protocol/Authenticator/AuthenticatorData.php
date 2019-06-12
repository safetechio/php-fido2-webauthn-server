<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;


class AuthenticatorData
{
    /** @var string $RPIDHash */
    public $RPIDHash;

    /** @var string $Flags */
    public $Flags;

    /** @var integer $Counter */
    public $Counter;

    /** @var AttestedCredentialData */
    public $AttData;

    /** @var string $ExtData */
    public $ExtData;
}