<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers;


use CBOR\Types\CBORByteString;
use SAFETECHio\FIDO2\Certificates\Certificate;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObject;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObjectFormat;
use SAFETECHio\FIDO2\WebAuthn\Protocol\COSE\COSE;
use SAFETECHio\FIDO2\WebAuthn\Protocol\COSE\PublicKeyFactory;

/**
 * Class FidoU2FAttestation
 * @package SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers
 * @see https://www.w3.org/TR/webauthn/#fido-u2f-attestation
 */
class FidoU2FAttestation implements AttestationFormatHandler
{
    /**
     * @param AttestationObject $attestationObject
     * @param string $clientDataHash
     * @throws WebAuthnException
     */
    public static function Verify(AttestationObject $attestationObject, string $clientDataHash)
    {
        // Check the the AAGUID is 16 zero bytes
        if(array_values(unpack('C*', $attestationObject->AuthData->AttData->AAGUID)) != [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]){
            throw new WebAuthnException(
                "Attestation AAGUID is not set to 0x00 for " . static::Name(),
                WebAuthnException::ATTESTATION_VERIFY_FAIL
            );
        }

        // Parse the public key
        $publicKey = PublicKeyFactory::Make($attestationObject->AuthData->AttData->CredentialPublicKey);

        //Check that the public key algorithm uses AlgES256
        if($publicKey->Algorithm != COSE::AlgES256){
            throw new WebAuthnException(
                "Attestation public is not AlgES256 received '". $publicKey->Algorithm ."' for " . static::Name(),
                WebAuthnException::ATTESTATION_VERIFY_FAIL
            );
        }

        // Check sig is set
        if(!isset($attestationObject->AttStatement["sig"])) {
            throw new WebAuthnException(
                "Attestation Statement sig not set for " . static::Name(),
                WebAuthnException::ATTESTATION_STATEMENT_SIG_NOT_SET
            );
        }

        // Check x5c is set
        if(!isset($attestationObject->AttStatement["x5c"])) {
            throw new WebAuthnException(
                "Attestation Statement x5c not set for " . static::Name(),
                WebAuthnException::ATTESTATION_STATEMENT_X5C_NOT_SET
            );
        }

        // Check x5c is an array
        if(!is_array($attestationObject->AttStatement["x5c"])) {
            throw new WebAuthnException(
                "Attestation Statement x5c not an array for " . static::Name(),
                WebAuthnException::ATTESTATION_STATEMENT_X5C_PARSE_FAILED
            );
        }

        // Check x5c has only one cert
        if(count($attestationObject->AttStatement["x5c"]) != 1) {
            throw new WebAuthnException(
                "Attestation Statement x5c has more than one cert for " . static::Name(),
                WebAuthnException::ATTESTATION_STATEMENT_X5C_PARSE_FAILED
            );
        }

        /** @var CBORByteString $x5c */
        $x5c = $attestationObject->AttStatement["x5c"][0];

        /** @var CBORByteString $sig */
        $sig = $attestationObject->AttStatement["sig"];

        //TODO refactor a lot of the checks into the Certificate class
        $cert = Certificate::ParseCertBytes($x5c->get_byte_string());

        // Check cert parsed correctly
        if(!$cert){
            throw new WebAuthnException(
                "Attestation Statement x5c cert failed to parse for " . static::Name(),
                WebAuthnException::ATTESTATION_STATEMENT_X5C_PARSE_FAILED
            );
        }

        // Check that the cert has not expired is not not yet valid
        if($cert["validFrom_time_t"] > time() || $cert["validTo_time_t"] < time()){
            throw new WebAuthnException(
                "Attestation Statement x5c cert time not valid. ".
                "Valid from = ".$cert["validFrom_time_t"].
                " , Valid to = ".$cert["validTo_time_t"].
                " , Server's current time = ".time().
                ". For "  . static::Name(),
                WebAuthnException::ATTESTATION_STATEMENT_X5C_INVALID_TIME
            );
        }

        // Create the data that was signed
        /** @see https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html#registration-response-message-success */
        $signatureData = "\0";
        $signatureData .= $attestationObject->AuthData->RPIDHash;
        $signatureData .= $clientDataHash;
        $signatureData .= $attestationObject->AuthData->AttData->CredentialID;
        $signatureData .= "\x04" . $publicKey->XCoord . $publicKey->YCoord;

        $attestationCert = Certificate::convertDERToPEM($x5c->get_byte_string());
        $signatureHashAlg = COSE::GetOpenSSLHashAlg($publicKey->Algorithm);

        $verifyResult = openssl_verify($signatureData, $sig->get_byte_string(), $attestationCert, $signatureHashAlg);
        if($verifyResult !== 1){
            throw new WebAuthnException(
                "Attestation signature verify failed for " . static::Name(),
                WebAuthnException::ATTESTATION_VERIFY_FAIL
            );
        }
    }

    public static function Name(): string
    {
        return AttestationObjectFormat::FIDO_U2F;
    }
}