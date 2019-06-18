<?php
/**
 * Created by IntelliJ IDEA.
 * User: samyo
 * Date: 15/06/2019
 * Time: 00:04
 */

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers;


use SAFETECHio\FIDO2\Certificates\Certificate;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObject;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObjectFormat;
use SAFETECHio\FIDO2\WebAuthn\Protocol\COSE\COSE;


/**
 * Class PackedAttestation
 * @package SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers
 * @see https://www.w3.org/TR/webauthn/#packed-attestation
 *
 * Certificate Attestation
 *  {
 *      alg: COSEAlgorithmIdentifier,
 *	 	sig: bytes,
 *      x5c: [ attestnCert: bytes, * (caCert: bytes) ]
 *  }
 *
 * ECDAA Attestation
 *  {
 *      alg: COSEAlgorithmIdentifier, (-260 for ED256 / -261 for ED512)
 *      sig: bytes,
 *      ecdaaKeyId: bytes
 *  }
 *
 * Self Attestation
 *  {
 *      alg: COSEAlgorithmIdentifier
 *      sig: bytes,
 *  }
 */
class PackedAttestation implements AttestationFormatHandler
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
                "Attestation Statement alg not set for packed format",
                WebAuthnException::ATTESTATION_STATEMENT_ALG_NOT_SET
            );
        }

        // Check sig is set and get value
        if(!isset($attestationObject->AttStatement["sig"])) {
            throw new WebAuthnException(
                "Attestation Statement sig not set for packed format",
                WebAuthnException::ATTESTATION_STATEMENT_SIG_NOT_SET
            );
        }

        // Check x5c is set
        if(isset($attestationObject->AttStatement["x5c"])) {
            static::handleCertificateAttestation($attestationObject, $clientDataHash);
        }

        // TODO add other packed type attestation verification processes
    }

    /**
     * @return string
     */
    public static function Name(): string
    {
        return AttestationObjectFormat::PACKED;
    }

    /**
     * @param AttestationObject $attestationObject
     * @param string $clientDataHash
     * @throws WebAuthnException
     */
    protected static function handleCertificateAttestation(AttestationObject $attestationObject, string $clientDataHash)
    {
        // Check all the certs in the chain
        foreach ($attestationObject->AttStatement["x5c"] as $i => $x5c) {
            $cert = Certificate::ParseCertBytes($x5c->get_byte_string());

            // Check cert parsed correctly
            if(!$cert){
                throw new WebAuthnException(
                    "Attestation Statement x5c cert failed to parse, on index $i for packed format",
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
                    ". For packed format",
                    WebAuthnException::ATTESTATION_STATEMENT_X5C_INVALID_TIME
                );
            }
        }

        $signatureData = $attestationObject->RawAuthData . $clientDataHash;
        $attestationCert = Certificate::convertDERToPEM($attestationObject->AttStatement["x5c"][0]->get_byte_string());
        $signatureHashAlg = COSE::GetOpenSSLHashAlg($attestationObject->AttStatement["alg"]);

        $verifyResult = openssl_verify($signatureData, $attestationObject->AttStatement["sig"]->get_byte_string(), $attestationCert, $signatureHashAlg);
        if($verifyResult !== 1){
            throw new WebAuthnException(
                "Attestation signature verify failed for packed format",
                WebAuthnException::ATTESTATION_VERIFY_FAIL
            );
        }

        // TODO add certificate checks
    }
}