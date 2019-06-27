<?php

namespace SAFETECHio\FIDO2\WebAuthn;


use SAFETECHio\FIDO2\Tools\Tools;

class Credential implements \JsonSerializable
{
    /** @var string $ID */
    public $ID;

    /** @var string $PublicKey */
    public $PublicKey;

    /** @var string $AttestationType */
    public $AttestationType;

    /** @var Authenticator $Authenticator */
    public $Authenticator;

    /**
     * Credential constructor.
     * @param string $id
     * @param string $publicKey
     * @param string $attestationType
     * @param Authenticator $authenticator
     */
    public function __construct(string $id, string $publicKey, string $attestationType, Authenticator $authenticator)
    {
        $this->ID = $id;
        $this->PublicKey = $publicKey;
        $this->AttestationType = $attestationType;
        $this->Authenticator = $authenticator;
    }

    /**
     * @return array
     */
    public function jsonSerialize(): array
    {
        return [
            "ID" => Tools::base64u_encode($this->ID),
            "PublicKey" => Tools::base64u_encode($this->PublicKey),
            "AttestationType" => $this->AttestationType,
            "Authenticator" => $this->Authenticator,
        ];
    }
}