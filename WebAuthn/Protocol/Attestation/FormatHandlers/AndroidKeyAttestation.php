<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers;

use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObject;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObjectFormat;

/** @see https://www.w3.org/TR/webauthn/#android-key-attestation */
class AndroidKeyAttestation implements AttestationFormatHandler
{
    /**
     * @param AttestationObject $attestationObject
     * @param string $clientDataHash
     * @throws WebAuthnException
     */
    public static function Verify(AttestationObject $attestationObject, string $clientDataHash)
    {
        // Check alg is set and get value
        if(!isset($attestationObject->AttStatement["alg"])) {
            throw new WebAuthnException(
                "Attestation Statement alg not set for android key",
                WebAuthnException::ATTESTATION_STATEMENT_ALG_NOT_SET
            );

        }
        $alg = (int) $attestationObject->AttStatement["alg"];

        // Check sig is set and get value
        if(!isset($attestationObject->AttStatement["sig"])) {
            throw new WebAuthnException(
                "Attestation Statement sig not set for android key",
                WebAuthnException::ATTESTATION_STATEMENT_SIG_NOT_SET
            );

        }
        $sig = (string) $attestationObject->AttStatement["sig"]->get_byte_string();

        // Check x5c is set and get cert value
        if(!isset($attestationObject->AttStatement["x5c"]) || !isset($attestationObject->AttStatement["x5c"][0])) {
            throw new WebAuthnException(
                "Attestation Statement x5c not set for android key",
                WebAuthnException::ATTESTATION_STATEMENT_X5C_NOT_SET
            );

        }
        $attestationCertificateData = (string) $attestationObject->AttStatement["x5c"][0]->get_byte_string();

        // Concatenate raw auth data and the att cert data to create and parse the
        $sigData = $attestationObject->RawAuthData . $attestationCertificateData;
        $attestationCertificate = openssl_x509_parse($sigData);

        // TODO complete, maybe once I have an example.
    }

    /**
     * @return string
     */
    public static function Name():string
    {
        return AttestationObjectFormat::ANDROID_KEY;
    }
}