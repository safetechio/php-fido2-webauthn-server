<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;

class CredentialCreation
{
    /** @var PublicKeyCredentialCreationOptions $Response */
    protected $Response;

    /**
     * CredentialCreation constructor.
     * @param PublicKeyCredentialCreationOptions $creationOptions
     */
    public function __construct(PublicKeyCredentialCreationOptions $creationOptions)
    {
        $this->Response = $creationOptions;
    }
}