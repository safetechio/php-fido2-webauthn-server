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
}