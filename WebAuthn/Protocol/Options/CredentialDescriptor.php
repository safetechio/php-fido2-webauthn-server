<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;

/** See Credential Descriptor https://www.w3.org/TR/webauthn/#credential-dictionary */
class CredentialDescriptor
{
    /** @var string $Type */
    public $Type;

    /** @var string $CredentialID */
    public $CredentialID;

    /**
     * @var string[] $Transport
     * use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator enums
     */
    public $Transport;
}