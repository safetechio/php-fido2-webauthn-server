<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Client;

use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\Tools\Tools;

/** @see https://www.w3.org/TR/webauthn/#sec-client-data */
class CollectedClientData
{
    /** @var string */
    public $Type;

    /** @var string $Challenge */
    public $Challenge;

    /** @var string $Origin */
    public $Origin;

    /** @var TokenBinding $TokenBinding */
    public $TokenBinding;

    /** @var string $Hint */
    public $Hint;

    public function __construct(string $clientDataJSON)
    {
        $clientData = Tools::base64u_decode($clientDataJSON);
        $decodedClientDataJson = json_decode($clientData, true);

        $this->Type = $decodedClientDataJson["type"];
        $this->Challenge = $decodedClientDataJson["challenge"];
        $this->Origin = $decodedClientDataJson["origin"];

        if(isset($decodedClientDataJson["hint"])){
            $this->Hint = $decodedClientDataJson["hint"];
        }

        if(isset($decodedClientDataJson["tokenBinding"])){
            $this->TokenBinding = new TokenBinding($decodedClientDataJson["tokenBinding"]);
        }
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credentia
     * @see https://www.w3.org/TR/webauthn/#verifying-assertion
     * @param string $challenge
     * @param string $ceremonyType
     * @param string $relyingPartyOrigin
     * @throws WebAuthnException | \ReflectionException
     */
    public function Verify(string $challenge, string $ceremonyType, string $relyingPartyOrigin)
    {
        // Check the ceremony type matches
        if ($this->Type != $ceremonyType){
            throw new WebAuthnException(
                "Client ceremony type does not match. Expected $ceremonyType, received $this->Type",
                WebAuthnException::CLIENT_CEREMONY_TYPE_MISMATCH
            );
        }

        // Check that the challenge matches
        if(!hash_equals($this->Challenge, $challenge)) {
            throw new WebAuthnException(
                "Challenge does not match. Expected $challenge, received $this->Challenge",
                WebAuthnException::CLIENT_CHALLENGE_MISMATCH
            );
        }

        // Check that the relying party origin matches
        if(strcmp($this->Origin, $relyingPartyOrigin) !== 0) {
            throw new WebAuthnException(
                "Origin does not match. Expected $relyingPartyOrigin, received $this->Origin",
                WebAuthnException::CLIENT_ORIGIN_MISMATCH
            );
        }

        // Check the token binding is set
        if($this->TokenBinding != null) {

            // If the token binding is set check that the status is also set
            if($this->TokenBinding->Status == "") {
                throw new WebAuthnException(
                    "Token Binding is set but has no status value",
                    WebAuthnException::CLIENT_TOKEN_BINDING_MISSING_STATUS
                );
            }

            // Check that the token binding status is a known value
            if(!in_array($this->TokenBinding->Status, TokenBindingStatus::All())) {
                throw new WebAuthnException(
                    "Token Binding status has unknown value : " . $this->TokenBinding->Status,
                    WebAuthnException::CLIENT_TOKEN_BINDING_UNKNOWN_STATUS
                );
            }
        }
    }
}