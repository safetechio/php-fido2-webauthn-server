<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Assertion;


use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\AuthenticatorResponse;

class AuthenticatorAssertionResponse extends AuthenticatorResponse
{
    /** @var string $AuthenticatorData */
    public $AuthenticatorData;

    /** @var string $Signature */
    public $Signature;

    /** @var string $UserHandle */
    public $UserHandle;

    public function __construct(array $response)
    {
        $this->AuthenticatorData = Tools::base64u_decode($response["authenticatorData"]);
        $this->ClientDataJSON = $response["clientDataJSON"];
        $this->Signature = Tools::base64u_decode($response["signature"]);
        $this->UserHandle = Tools::base64u_decode($response["userHandle"]);
    }
}