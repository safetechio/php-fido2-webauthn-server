<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;

use SAFETECHio\FIDO2\WebAuthn\Protocol\Entities\RelyingPartyEntity;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Entities\UserEntity;

/** See Options for Credential Creation https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions */
class PublicKeyCredentialCreationOptions implements \JsonSerializable
{
    /** @var string $Challenge */
    public $Challenge;

    /** @var RelyingPartyEntity $RelyingParty */
    public $RelyingParty;

    /** @var UserEntity $User */
    public $User;

    /** @var CredentialParameter[] $Parameters */
    public $Parameters;

    /** @var AuthenticatorSelection $AuthenticatorSelection */
    public $AuthenticatorSelection;

    /** @var integer $Timeout */
    public $Timeout;

    /** @var CredentialDescriptor[]  */
    public $CredentialExcludeList;

    /** @var AuthenticationExtensionsClientInputs $Extensions */
    public $Extensions;

    /** @var string $Attestation */
    public $Attestation;

    public function jsonSerialize()
    {
        $outPut = [
            "challenge" => $this->Challenge,
            "rp" => $this->RelyingParty,
            "user" => $this->User
        ];

        if(count($this->Parameters) > 0) {
            $outPut["pubKeyCredParams"] = $this->Parameters;
        }

        if($this->AuthenticatorSelection !== null){
            $outPut["authenticatorSelection"] = $this->AuthenticatorSelection;
        }

        if($this->Timeout != 0){
            $outPut["timeout"] = $this->Timeout;
        }

        if(count($this->CredentialExcludeList) > 0){
            $outPut["excludeCredentials"] = $this->CredentialExcludeList;
        }

        if(count($this->Extensions) > 0){
            $outPut["extensions"] = $this->Extensions;
        }

        if(strlen($this->Attestation) > 0){
            $outPut["attestation"] = $this->Attestation;
        }

        return $outPut;
    }
}
