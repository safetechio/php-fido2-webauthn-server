<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials;

/** See https://w3c.github.io/webappsec-credential-management/#credential */
class Credential implements \JsonSerializable
{
    /** @var string $ID */
    public $ID;

    /** @var string $Type */
    public $Type;

    public function jsonSerialize()
    {
        return [
            "id" => $this->ID,
            "type" => $this->Type,
        ];
    }
}