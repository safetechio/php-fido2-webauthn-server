<?php

namespace SAFETECHio\FIDO2\WebAuthn;

class SessionData
{
    /** @var string $Challenge */
    public $Challenge;

    /** @var string $UserID */
    public $UserID;

    /** @var string[] $AllowedCredentialIDs */
    public $AllowedCredentialIDs;

    /** @var string $UserVerification */
    public $UserVerification;
}