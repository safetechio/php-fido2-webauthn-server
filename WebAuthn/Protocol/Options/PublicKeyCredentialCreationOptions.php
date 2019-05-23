<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;

use SAFETECHio\FIDO2\WebAuthn\Contracts\User;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Entities\RelyingPartyEntity;

/** See Options for Credential Creation https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions */
class PublicKeyCredentialCreationOptions
{
    /** @var string $Challenge */
    public $Challenge;

    /** @var RelyingPartyEntity $RelyingParty */
    public $RelyingParty;

    /** @var User $User */
    public $User;

    /** @var CredentialParameter[] $Parameters */
    public $Parameters;

    /** @var AuthenticatorSelection $AuthenticatorSelection */
    public $AuthenticatorSelection;

    /** @var integer $Timeout */
    public $Timeout;

    public $CredentialExcludeList;
    public $Extensions;

    /** @var string $Attestation */
    public $Attestation;
}
