<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials;

use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AuthenticatorAttestationResponse;

class CredentialCreationResponse extends PublicKeyCredential
{
    /** @var AuthenticatorAttestationResponse $AttestationResponse */
    public $AttestationResponse;

    /**
     * CredentialCreationResponse constructor.
     * @param string $credentialCreationJSON
     * @throws WebAuthnException
     */
    public function __construct(string $credentialCreationJSON)
    {
        $json = json_decode($credentialCreationJSON, true);
        $this->validate($json);

        $this->ID = $json["id"];
        $this->Type = $json["type"];
        $this->RawID = $json["rawId"];

        if(isset($json["extensions"])){
            $this->Extensions = $json["extensions"];
        }

        $this->AttestationResponse = new AuthenticatorAttestationResponse($json["response"]);
    }

    /**
     * @param array $json
     * @throws WebAuthnException
     */
    protected function validate(array $json)
    {
        // Check the raw id and the id match after they have both been decoded
        $id = Tools::base64u_decode($json['id']);
        $rawId = Tools::base64u_decode($json['rawId']);
        if(!hash_equals($id, $rawId)){
            throw new WebAuthnException(
                "Hash mismatch: id and rawId should match: $id - $rawId",
                WebAuthnException::HASH_MISMATCH
            );
        }

        // TODO some more validation of the JSON
    }
}