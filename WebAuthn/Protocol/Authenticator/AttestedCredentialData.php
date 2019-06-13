<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;

use CBOR\CBOREncoder;

/** See https://www.w3.org/TR/webauthn/#attested-credential-data */
class AttestedCredentialData
{
    /**
    |--------------------------------------------------------------------------
    | Attested Credential Data Constants
    |--------------------------------------------------------------------------
    |
    | These constants define where library should look to find the different
    | elements of the Attested Credential Data from the raw auth data
    |
    */

    const AAGUIDPosition = AuthenticatorData::MinDataLength;

    const AAGUIDLength = 16;

    const CredentialIDLengthPosition = AuthenticatorData::MinDataLength + AttestedCredentialData::AAGUIDLength;

    const CredentialIDLengthLength = 2;

    const CredentialIDPosition = AuthenticatorData::MinDataLength + AttestedCredentialData::AAGUIDLength + AttestedCredentialData::CredentialIDLengthLength;


    /** @var string $AAGUID */
    public $AAGUID;

    /** @var int $CredentialIDLength */
    public $CredentialIDLength;

    /** @var string $CredentialID */
    public $CredentialID;

    /** @var string $CredentialPublicKey */
    public $CredentialPublicKey;

    /** @var int $Length */
    public $Length;


    /**
     * See https://www.w3.org/TR/webauthn/#attested-credential-data
     * @param string $rawAuthData
     * @return AttestedCredentialData
     * @throws \Exception
     */
    public static function FromRawAuthData($rawAuthData): AttestedCredentialData
    {
        $out = new static;

        $out->AAGUID = substr($rawAuthData, static::AAGUIDPosition,static::AAGUIDLength);
        $out->CredentialIDLength = unpack("n", (substr($rawAuthData, static::CredentialIDLengthPosition, static::CredentialIDLengthLength)))[1];
        $out->CredentialID = substr($rawAuthData, static::CredentialIDPosition, $out->CredentialIDLength);

        // Calculate the public key
        // Decode the remaining raw bytes from parsing the attested data. This will return a CBOR object
        $remainingRawData = substr($rawAuthData, static::CredentialIDPosition + $out->CredentialIDLength);
        $decodedPublicKey = CBOREncoder::decode($remainingRawData);

        // Re-encode the CBOR object into a CBOR string.
        // This will give us the bytes we need to work out if there is any more data left in the raw Auth data
        $out->CredentialPublicKey = CBOREncoder::encode($decodedPublicKey);

        // Set the object's data length
        $out->Length = strlen($out->AAGUID) + static::CredentialIDLengthLength + strlen($out->CredentialID) + strlen($out->CredentialPublicKey);

        return $out;
    }
}