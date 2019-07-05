<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Assertion;


use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\AuthenticatorData;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Client\CollectedClientData;

class ParsedAssertionResponse
{
    /** @var CollectedClientData $CollectedClientData */
    public $CollectedClientData;

    /** @var AuthenticatorData $AuthenticatorData */
    public $AuthenticatorData;

    /** @var string $Signature */
    public $Signature;

    /** @var string $UserHandle */
    public $UserHandle;

    /**
     * ParsedAssertionResponse constructor.
     * @param AuthenticatorAssertionResponse $authenticatorAssertionResponse
     * @throws \SAFETECHio\FIDO2\Exceptions\WebAuthnException
     */
    public function __construct(AuthenticatorAssertionResponse $authenticatorAssertionResponse)
    {
        $this->CollectedClientData = new CollectedClientData($authenticatorAssertionResponse->ClientDataJSON);
        $this->AuthenticatorData = AuthenticatorData::ParseRawAuthData($authenticatorAssertionResponse->AuthenticatorData);
        $this->Signature = $authenticatorAssertionResponse->Signature;
        $this->UserHandle = $authenticatorAssertionResponse->UserHandle;
    }
}