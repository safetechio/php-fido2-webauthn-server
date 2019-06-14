<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation;


use CBOR\CBOREncoder;
use CBOR\Types\CBORByteString;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\AuthenticatorData;

/** See AttestationObject https://www.w3.org/TR/webauthn/#attestation-object */
class AttestationObject
{
    /** @var AuthenticatorData $AuthData */
    public $AuthData;

    /** @var string $RawAuthData */
    public $RawAuthData;

    /** @var string $Format */
    public $Format;

    /** @var array $AttStatement */
    public $AttStatement;

    /**
     * AttestationObject constructor.
     * @param $AttestationObjectJSON
     * @throws WebAuthnException | \Exception
     */
    public function __construct(string $AttestationObjectJSON)
    {
        $base64Decode = Tools::base64u_decode($AttestationObjectJSON);
        $decodedAttestationObject = CBOREncoder::decode($base64Decode);

        /** @var CBORByteString $decodedAttestationObject["authData"] */
        $this->RawAuthData = $decodedAttestationObject["authData"]->get_byte_string();
        $this->Format = $decodedAttestationObject["fmt"];
        $this->AttStatement = $decodedAttestationObject["attStmt"];
        $this->AuthData = AuthenticatorData::ParseRawAuthData($this->RawAuthData);
    }

    /**
     * @param bool $verifyUser
     * @param string $relyingPartyID
     * @param string $ClientDataJSON
     * @throws WebAuthnException | \ReflectionException
     */
    public function Verify(bool $verifyUser, string $relyingPartyID, string $ClientDataJSON)
    {
        // Calculate the SHA256 hash of the Client Data JSON
        $clientDataJSONHash = Tools::SHA256($ClientDataJSON);

        // Calculate the SHA256 hash of the Relying Party ID
        $relyingPartyIDHash = Tools::SHA256($relyingPartyID);

        // Verify the Auth Data
        $this->AuthData->Verify($verifyUser, $relyingPartyIDHash);

        // Check the Format is of a know type
        if(!AttestationObjectFormat::Has($this->Format)) {
            throw new WebAuthnException(
                "Attestation Object Format unknown, received $this->Format",
                WebAuthnException::ATTESTATION_FORMAT_UNKNOWN_TYPE
            );
        }

        // Check the format of the Attestation Object is "none"
        if($this->Format == AttestationObjectFormat::NONE) {

            // Check the attestation statement is empty, if it isn't we have a problem
            if(!empty($this->AttStatement)) {
                throw new WebAuthnException(
                    "Attestation Format set to 'none', but Attestation Statement is present",
                    WebAuthnException::ATTESTATION_FORMAT_NONE_STATEMENT_SET
                );
            }

            // Otherwise stop the Verification process at this stage
            return;
        }

        // TODO add attestation format handling
    }
}