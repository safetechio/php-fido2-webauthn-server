<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials;


class PublicKeyCredential extends Credential
{
    /** @var string $RawID */
    public $RawID;

    /** @var array */
    public $Extensions;

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();
        $json["rawId"] = $this->RawID;

        if(count($this->Extensions) > 0){
            $json["extensions"] = $this->Extensions;
        }
    }
}