<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;


use SAFETECHio\FIDO2\Tools\Tools;

class PublicKeyCredentialRequestOptions implements \JsonSerializable
{
    /** @var string $Challenge */
    public $Challenge;

    /** @var int $Timeout */
    public $Timeout;

    /** @var string $RelyingPartyID */
    public $RelyingPartyID;

    /** @var CredentialDescriptor[] $AllowedCredentials */
    public $AllowedCredentials;

    /** @var string $UserVerification */
    public $UserVerification;

    /** @var array $Extensions */
    public $Extensions;

    /**
     * @return array
     */
    public function AllowedCredentialIDs()
    {
        $out = [];
        foreach ($this->AllowedCredentials as $credential)
        {
            $out[] = $credential->CredentialID;
        }

        return $out;
    }

    /**
     * @return array
     */
    public function jsonSerialize(): array
    {
        $json = [
            "challenge" => Tools::base64u_encode($this->Challenge)
        ];

        if(isset($this->Timeout) || $this->Timeout != 0){
            $json["timeout"] = $this->Timeout;
        }

        if(isset($this->RelyingPartyID) || $this->RelyingPartyID != ""){
            $json["rpId"] = $this->RelyingPartyID;
        }

        if(count($this->AllowedCredentials) > 0){
            $json["allowCredentials"] = $this->AllowedCredentials;
        }

        if(isset($this->UserVerification) || $this->UserVerification != ""){
            $json["userVerification"] = $this->UserVerification;
        }

        if(count($this->Extensions) > 0){
            $json["userVerification"] = $this->Extensions;
        }

        return $json;
    }
}