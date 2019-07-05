<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Assertion;


use SAFETECHio\FIDO2\WebAuthn\Protocol\Credentials\ParsedPublicKeyCredential;

class ParsedCredentialAssertionData extends ParsedPublicKeyCredential
{
    /** @var ParsedAssertionResponse $Response */
    public $Response;

    /** @var CredentialAssertionResponse $Raw */
    public $Raw;

    /**
     * ParsedCredentialAssertionData constructor.
     * @param CredentialAssertionResponse $credentialAssertionResponse
     * @throws \SAFETECHio\FIDO2\Exceptions\WebAuthnException
     */
    public function __construct(CredentialAssertionResponse $credentialAssertionResponse)
    {
        $this->Raw = $credentialAssertionResponse;
        $this->ID = $credentialAssertionResponse->ID;
        $this->RawID = $credentialAssertionResponse->RawID;
        $this->Type = $credentialAssertionResponse->Type;
        $this->Response = new ParsedAssertionResponse($credentialAssertionResponse->AssertionResponse);
    }
}