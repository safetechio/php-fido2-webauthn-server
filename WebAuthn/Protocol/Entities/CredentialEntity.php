<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Entities;

/** See https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity */
class CredentialEntity implements \JsonSerializable
{
    /** @var string $Name */
    public $Name;

    /** @var string $Icon*/
	public $Icon;

	public function jsonSerialize(): array
    {
        $json = [
            "name" => $this->Name
        ];

        if(strlen($this->Icon) > 0){
            $json["icon"] = $this->Icon;
        }

        return $json;
    }
}