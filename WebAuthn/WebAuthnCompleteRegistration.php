<?php

namespace SAFETECHio\FIDO2\WebAuthn;

use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Contracts\User;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AuthenticatorAttestationResponse;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials\CredentialCreationResponse;

class WebAuthnCompleteRegistration
{
    /**
     * @var User $user
     */
    protected $user;

    /** @var SessionData $sessionData */
    protected $sessionData;

    /** @var string $credentialCreationJSON */
    protected $credentialCreationJSON;

    /**
     * WebAuthnCompleteRegistration constructor.
     * @param User $user
     * @param SessionData $sessionData
     * @param string $credentialCreationJSON
     * @throws WebAuthnException
     */
    public function __construct(User $user, SessionData $sessionData, string $credentialCreationJSON)
    {
        // Check that the user ID and session userId Match
        if($user->WebAuthnID() != $sessionData->UserID){
            throw new WebAuthnException(
                "ID Mismatch: User ID and session's User ID do not match",
                WebAuthnException::ID_MISMATCH
            );
        }

        $parsedJson = $this->parseCredentialCreationJSON($credentialCreationJSON);
    }

    /**
     * @param string $credentialCreationJSON
     * @return string
     * @throws WebAuthnException | \Exception
     */
    protected function parseCredentialCreationJSON(string $credentialCreationJSON)
    {
        $json = json_decode($credentialCreationJSON, true);
        // TODO some validation of the JSON

        // Check the raw id and the id match after they have both been decoded
        $id = Tools::base64u_decode($json['id']);
        $rawId = Tools::base64u_decode($json['rawId']);
        if(!hash_equals($id, $rawId)){
            throw new WebAuthnException(
                "Hash mismatch: id and rawId should match: $id - $rawId",
                WebAuthnException::HASH_MISMATCH
            );
        }

        $credentialCreationResponse = new CredentialCreationResponse();
        $credentialCreationResponse->ID = $json["id"];
        $credentialCreationResponse->Type = $json["type"];
        $credentialCreationResponse->RawID = $json["rawId"];

        if(isset($json["extensions"])){
            $credentialCreationResponse->Extensions = $json["extensions"];
        }

        $authenticatorAttestationResponse = new AuthenticatorAttestationResponse();
        $authenticatorAttestationResponse->AttestationObject = $json["response"]["attestationObject"];
        $authenticatorAttestationResponse->ClientDataJSON = $json["response"]["clientDataJSON"];

        $parsedAttestationResponse = $authenticatorAttestationResponse->Parse();
        return "";
    }
}