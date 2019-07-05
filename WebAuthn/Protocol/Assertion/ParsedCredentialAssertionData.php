<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Assertion;


use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Client\CeremonyType;
use SAFETECHio\FIDO2\WebAuthn\Protocol\COSE\PublicKeyFactory;
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

    /**
     * @see https://www.w3.org/TR/webauthn/#verifying-assertion
     *
     * @param string $challenge
     * @param bool $verifyUser
     * @param string $relyingPartyID
     * @param string $relyingPartyOrigin
     * @param string $credentialPublicKey
     * @throws WebAuthnException | \ReflectionException
     */
    public function Verify(string $challenge, bool $verifyUser, string $relyingPartyID, string $relyingPartyOrigin, string $credentialPublicKey)
    {
        // Verify the client data against the stored relying party data
        $this->Response->CollectedClientData->Verify($challenge, CeremonyType::GET, $relyingPartyOrigin);

        // SHA256 hash the relying party id
        $RPIDHash = Tools::SHA256($relyingPartyID, true);

        // Verify the authenticator data object
        $this->Response->AuthenticatorData->Verify($verifyUser, $RPIDHash);

        // Hash client data JSON
        $clientDataHash = Tools::SHA256($this->Raw->AssertionResponse->ClientDataJSON, true);

        $signedData = $this->Raw->AssertionResponse->AuthenticatorData . $clientDataHash;

        $publicKey = PublicKeyFactory::Make($credentialPublicKey);

        if(!$publicKey->Verify($signedData, $this->Response->Signature)){
            throw new WebAuthnException(
                "Signature does not verify",
                WebAuthnException::ATTESTATION_SIGNATURE_INVALID
            );
        }
    }
}