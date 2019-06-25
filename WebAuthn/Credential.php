<?php

namespace SAFETECHio\FIDO2\WebAuthn;


class Credential
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
}