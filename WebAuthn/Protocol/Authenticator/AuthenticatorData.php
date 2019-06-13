<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;

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
     * @param string $data
     * @return AuthenticatorData
     * @throws WebAuthnException
     */
    public static function ParseRawAuthData(string $data): AuthenticatorData
    {
        // Validation, check that the incoming data is longer than the minimum length.
        if(static::MinDataLength > strlen($data)){
            throw new WebAuthnException(
                "Expected data longer than " .static::MinDataLength. " bytes. Received " .strlen($data). " bytes",
                WebAuthnException::AUTHENTICATOR_DATA_TOO_SHORT
            );
        }

        // Create a new AuthenticatorData object and assign the mandatory data to it
        $out = new static;

        $out->RPIDHash = substr($data, 0, 32);
        $out->Flags = new AuthenticatorFlags(substr($data, 32, 1));
        $out->Counter = unpack("N", substr($data, 33, 4))[1];

        $remainingLength = strlen($data) - static::MinDataLength;

        // TODO handler the remainder of the data

        return $out;
    }
}