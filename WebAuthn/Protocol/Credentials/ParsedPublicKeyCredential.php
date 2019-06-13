<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials;


class ParsedPublicKeyCredential extends ParsedCredential
{
    /** @var string $RawID */
    public $RawID;

    /** @var array */
    public $Extensions;
}