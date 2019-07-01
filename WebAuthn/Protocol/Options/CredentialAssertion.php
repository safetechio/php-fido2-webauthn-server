<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;

class CredentialAssertion implements \JsonSerializable
{
    /** @var PublicKeyCredentialRequestOptions $Response */
    protected $Response;

    /**
     * CredentialCreation constructor.
     * @param PublicKeyCredentialRequestOptions $creationOptions
     */
    public function __construct(PublicKeyCredentialRequestOptions $creationOptions)
    {
        $this->Response = $creationOptions;
    }

    public function jsonSerialize()
    {
        return[
            "publicKey" => $this->Response
        ];
    }
}