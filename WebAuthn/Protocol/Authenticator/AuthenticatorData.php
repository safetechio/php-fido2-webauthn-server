<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;

use SAFETECHio\FIDO2\Exceptions\WebAuthnException;


/** See https://www.w3.org/TR/webauthn/#table-authData */
class AuthenticatorData
{
    /*
    |--------------------------------------------------------------------------
    | Authenticator Data Constants
    |--------------------------------------------------------------------------
    |
    | These constants define where library should look to find the different
    | elements of the Authenticator Data from the raw auth data.
    |
    | These constants are here to prevent introducing bugs if in future this
    | part of the code base needs to be changed.
    |
    */

    /** @var int RPIDHashPosition */
    const RPIDHashPosition = 0;

    /** @var int RPIDHashLength */
    const RPIDHashLength = 32;

    /** @var int FlagsPosition */
    const FlagsPosition = AuthenticatorData::RPIDHashLength;

    /** @var int FlagsLength */
    const FlagsLength = 1;

    /** @var int CounterPosition */
    const CounterPosition = AuthenticatorData::RPIDHashLength + AuthenticatorData::FlagsLength;

    /** @var int CounterLength */
    const CounterLength = 4;

    /** @var int $minDataLength */
    const MinDataLength = AuthenticatorData::RPIDHashLength + AuthenticatorData::FlagsLength + AuthenticatorData::CounterLength;



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

        $out->RPIDHash = substr($rawAuthData, static::RPIDHashPosition, static::RPIDHashLength);
        $out->Flags = new AuthenticatorFlags(substr($rawAuthData, static::FlagsPosition, static::FlagsLength));
        $out->Counter = unpack("N", substr($rawAuthData, static::CounterPosition, static::CounterLength))[1];

        $remainingLength = strlen($rawAuthData) - static::MinDataLength;

        // Handle the remainder of the data
        // Check if there is any Attested Credential Data, if so parse it
        if ($out->Flags->HasAttestedCredentialData()) {
		    if (strlen($rawAuthData) > static::MinDataLength) {
		        $out->AttData = AttestedCredentialData::FromRawAuthData($rawAuthData);
                $remainingLength = $remainingLength - $out->AttData->Length;
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

        // Check if there are any extensions, if so parse them
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

        // If there is still bytes remaining then something is wrong
        if ($remainingLength != 0) {
            throw new WebAuthnException(
                "Bytes remaining after decoding the AuthenticatorData",
                WebAuthnException::AUTHENTICATOR_REMAINING_BYTES
            );
	    }

        return $out;
    }
}