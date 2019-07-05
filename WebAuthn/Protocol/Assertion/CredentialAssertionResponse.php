<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Assertion;

use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials\PublicKeyCredential;

class CredentialAssertionResponse extends PublicKeyCredential
{
    /** @var AuthenticatorAssertionResponse */
    public $AssertionResponse;

    /**
     * CredentialAssertionResponse constructor.
     * @param string $credentialAssertionJSON
     * @throws WebAuthnException
     */
    public function __construct(string $credentialAssertionJSON)
    {
        $json = json_decode($credentialAssertionJSON, true);
        $this->validate($json);

        $this->ID = $json["id"];
        $this->Type = $json["type"];
        $this->RawID = $json["rawId"];

        if(isset($json["extensions"])){
            $this->Extensions = $json["extensions"];
        }

        $this->AssertionResponse = new AuthenticatorAssertionResponse($json["response"]);
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