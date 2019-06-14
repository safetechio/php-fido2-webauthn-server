<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Client;


class TokenBinding
{
    /** @var string $Status */
    public $Status;

    /** @var string $ID */
    public $ID;

    public function __construct(array $tokenBindingJson)
    {
        $this->ID = $tokenBindingJson["id"];
        $this->Status = $tokenBindingJson["status"];
    }
}