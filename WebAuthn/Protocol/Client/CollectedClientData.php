<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Client;

use SAFETECHio\FIDO2\Tools\Tools;

/** See https://www.w3.org/TR/webauthn/#sec-client-data */
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
}