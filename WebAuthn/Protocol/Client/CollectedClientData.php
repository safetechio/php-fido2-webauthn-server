<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Client;

/** See https://www.w3.org/TR/webauthn/#sec-client-data */
class CollectedClientData
{
    /** @var string */
    public $Type;

    /** @var string $Challenge */
    public $Challenge;

    /** @var string $Origin */
    public $Origin;

    /** @var TokenBinding $TokenBinding */
    public $TokenBinding;

    /** @var string $Hint */
    public $Hint;
}