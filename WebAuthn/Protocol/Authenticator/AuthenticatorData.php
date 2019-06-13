<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;

use CBOR\CBOREncoder;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;


/** See https://www.w3.org/TR/webauthn/#table-authData */
class AuthenticatorData
{
    /** @var int $minDataLength */
    const MinDataLength = 37;

    /** @var string $RPIDHash */
    public $RPIDHash;

    /** @var AuthenticatorFlags $Flags */
    public $Flags;

    /** @var integer $Counter */
    public $Counter;

    /** @var AttestedCredentialData */
    public $AttData;

    /** @var string $ExtData */
    public $ExtData;

    /**
     * @param string $rawAuthData
     * @return AuthenticatorData
     * @throws WebAuthnException | \Exception
     */
    public static function ParseRawAuthData(string $rawAuthData): AuthenticatorData
    {
        // Validation, check that the incoming data is longer than the minimum length.
        if(static::MinDataLength > strlen($rawAuthData)){
            throw new WebAuthnException(
                "Expected data longer than " .static::MinDataLength. " bytes. Received " .strlen($rawAuthData). " bytes",
                WebAuthnException::AUTHENTICATOR_DATA_TOO_SHORT
            );
        }

        // Create a new AuthenticatorData object and assign the mandatory data to it
        $out = new static;

        $out->RPIDHash = substr($rawAuthData, 0, 32);
        $out->Flags = new AuthenticatorFlags(substr($rawAuthData, 32, 1));
        $out->Counter = unpack("N", substr($rawAuthData, 33, 4))[1];

        $remainingLength = strlen($rawAuthData) - static::MinDataLength;

        // Handle the remainder of the data

        if ($out->Flags->HasAttestedCredentialData()) {
		    if (strlen($rawAuthData) > static::MinDataLength) {
                $out->parseAttestedData($rawAuthData);
			    $attDataLength = strlen($out->AttData->AAGUID) + 2 + strlen($out->AttData->CredentialID) + strlen($out->AttData->CredentialPublicKey);
                $remainingLength = $remainingLength - $attDataLength;
		    } else {
                throw new WebAuthnException(
                    "Attested credential flag is set but attested credential data is missing",
                    WebAuthnException::AUTHENTICATOR_CREDENTIAL_DATA_MISSING
                );
		    }
        } else {
            if(!$out->Flags->HasExtensions() && strlen($rawAuthData) != 37) {
                throw new WebAuthnException(
                    "Attested credential flag is not set but extra data is present",
                    WebAuthnException::AUTHENTICATOR_CREDENTIAL_FLAG_MISSING
                );
            }
        }

        if ($out->Flags->HasExtensions()) {
		    if ($remainingLength != 0) {
                $out->ExtData = substr($rawAuthData, -$remainingLength, $remainingLength);
                $remainingLength = $remainingLength - strlen($out->ExtData);
            } else {
                throw new WebAuthnException(
                    "Extensions flag is set but extensions data is missing",
                    WebAuthnException::AUTHENTICATOR_EXTENSION_DATA_MISSING
                );
            }
        }

        if ($remainingLength != 0) {
            throw new WebAuthnException(
                "Bytes remaining after decoding the AuthenticatorData",
                WebAuthnException::AUTHENTICATOR_REMAINING_BYTES
            );
	    }

        return $out;
    }

    /**
     * See https://www.w3.org/TR/webauthn/#attested-credential-data
     * @param string $rawAuthData
     * @throws \Exception
     */
    protected function parseAttestedData($rawAuthData)
    {
        $this->AttData->AAGUID = substr($rawAuthData, 37,16);
        $idLength = unpack("n", (substr($rawAuthData, 53, 2)))[1];
        $this->AttData->CredentialID = substr($rawAuthData, 55, $idLength);

        // Calculate the public key
        // Decode the remaining raw bytes from parsing the attested data. This will return a CBOR object
        $remainingRawData = substr($rawAuthData, 55+$idLength);
        $decodedPublicKey = CBOREncoder::decode($remainingRawData);

        // Re-encode the CBOR object into a CBOR string.
        // This will give us the bytes we need to work out if there is any more data left in the raw Auth data
        $this->AttData->CredentialPublicKey = CBOREncoder::encode($decodedPublicKey);
    }
}