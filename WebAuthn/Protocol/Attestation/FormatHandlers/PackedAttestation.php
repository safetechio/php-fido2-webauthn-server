<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers;


use CBOR\CBOREncoder;
use CBOR\Types\CBORByteString;
use FreeDSx\Asn1\Encoders;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use SAFETECHio\FIDO2\Certificates\Certificate;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObject;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObjectFormat;
use SAFETECHio\FIDO2\WebAuthn\Protocol\COSE\COSE;
use SAFETECHio\FIDO2\WebAuthn\Protocol\COSE\PublicKeyFactory;


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
     * @throws EncoderException
     * @throws PartialPduException
     * @throws \Exception
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

        // Check x5c is set, if so handle Certificate Attestation
        if(isset($attestationObject->AttStatement["x5c"])) {
            return static::handleCertificateAttestation($attestationObject, $clientDataHash);
        }

        // Check ecdaaKeyId is set, if so handle ECDAA Attestation.
        if(isset($attestationObject->AttStatement["ecdaaKeyId"])){
            return static::handleECDAAAttestation($attestationObject, $clientDataHash);
        }

        return static::handleSelfAttestation($attestationObject, $clientDataHash);
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
     * @throws EncoderException
     * @throws PartialPduException
     */
    protected static function handleCertificateAttestation(AttestationObject $attestationObject, string $clientDataHash)
    {
        /** @var CBORByteString[] $x5cs */
        $x5cs = $attestationObject->AttStatement["x5c"];

        /** @var CBORByteString $sig */
        $sig = $attestationObject->AttStatement["sig"];

        //TODO refactor a lot of the checks into the Certificate class
        // Check all the certs in the chain
        foreach ($x5cs as $i => $x5c) {
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
        $attestationCert = Certificate::convertDERToPEM($x5cs[0]->get_byte_string());
        $signatureHashAlg = COSE::GetOpenSSLHashAlg($attestationObject->AttStatement["alg"]);

        $verifyResult = openssl_verify($signatureData, $sig->get_byte_string(), $attestationCert, $signatureHashAlg);
        if($verifyResult !== 1){
            throw new WebAuthnException(
                "Attestation signature verify failed for packed format",
                WebAuthnException::ATTESTATION_VERIFY_FAIL
            );
        }

        // Certificate checks
        $parsedCert = Certificate::ParseCertBytes($x5cs[0]->get_byte_string());

        // Check that the version is set
        if(!isset($parsedCert["version"])){
            throw new WebAuthnException(
                "Attestation certificate version missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that the version is valid
        if($parsedCert["version"] != 2){
            throw new WebAuthnException(
                "Attestation certificate has an invalid version. Received : ".$parsedCert["version"].", expected : 2, for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that subject is set
        if(!isset($parsedCert["subject"])){
            throw new WebAuthnException(
                "Attestation certificate subject is missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that subject Country is set
        if(!isset($parsedCert["subject"]["C"]) || $parsedCert["subject"]["C"] == ""){
            throw new WebAuthnException(
                "Attestation certificate subject country is missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that subject Organisation is set
        if(!isset($parsedCert["subject"]["O"]) || $parsedCert["subject"]["O"] == ""){
            throw new WebAuthnException(
                "Attestation certificate subject organisation is missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that subject Organisation Unit is set
        if(!isset($parsedCert["subject"]["OU"])){
            throw new WebAuthnException(
                "Attestation certificate subject organisation unit is missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that subject Organisation Unit is valid
        if($parsedCert["subject"]["OU"] != "Authenticator Attestation"){
            throw new WebAuthnException(
                "Attestation certificate subject organisation unit is invalid.".
                "Received : '".$parsedCert["subject"]["OU"].
                "' . Expected : 'Authenticator Attestation'. for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that subject Common Name is set
        if(!isset($parsedCert["subject"]["CN"]) || $parsedCert["subject"]["CN"] == ""){
            throw new WebAuthnException(
                "Attestation certificate subject common name is missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that extensions is set
        if(!isset($parsedCert["extensions"]) || empty($parsedCert["extensions"])){
            throw new WebAuthnException(
                "Attestation certificate extensions is missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that extensions OID 1.3.6.1.4.1.45724.1.1.4 id-fido-gen-ce-aaguid is set
        if(!isset($parsedCert["extensions"]["1.3.6.1.4.1.45724.1.1.4"])){
            throw new WebAuthnException(
                "Attestation certificate extensions OID 1.3.6.1.4.1.45724.1.1.4 id-fido-gen-ce-aaguid is missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Need to decode the cert's 1.3.6.1.4.1.45724.1.1.4 extension from an ASN1 octet string into a byte string
        // This is because X.509 encodes extensions using DER encoding in an OCTET STRING.
        $certAAGUID = Encoders::der()->decode($parsedCert["extensions"]["1.3.6.1.4.1.45724.1.1.4"])->getValue();

        // Check that extensions OID 1.3.6.1.4.1.45724.1.1.4 id-fido-gen-ce-aaguid matches the AttData AAGUID
        if(!hash_equals($certAAGUID, $attestationObject->AuthData->AttData->AAGUID)){
            throw new WebAuthnException(
                "Attestation certificate extensions OID 1.3.6.1.4.1.45724.1.1.4 id-fido-gen-ce-aaguid does not match the AttData AAGUID for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that extensions basicConstraints is set
        if(!isset($parsedCert['extensions']['basicConstraints'])){
            throw new WebAuthnException(
                "Attestation certificate extensions basicConstraints is missing for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

        // Check that extensions basicConstraints has CA disabled
        if('CA:FALSE' !== $parsedCert['extensions']['basicConstraints']){
            throw new WebAuthnException(
                "Attestation certificate extensions basicConstraints should be 'CA:FALSE', received : '".$parsedCert['extensions']['basicConstraints']."' for packed format",
                WebAuthnException::ATTESTATION_CERTIFICATE_INVALID
            );
        }

    }

    /**
     * @param AttestationObject $attestationObject
     * @param string $clientDataHash
     * @throws WebAuthnException
     */
    protected static function handleECDAAAttestation(AttestationObject $attestationObject, string $clientDataHash)
    {
        // At the moment the specification does not support ECDAA Attestation.
        throw new WebAuthnException(
            "ECDAA Attestation is not yet supported by the WebAuthn spec",
            WebAuthnException::ATTESTATION_TYPE_NOT_SUPPORTED
        );
    }

    /**
     * @param AttestationObject $attestationObject
     * @param string $clientDataHash
     * @throws \Exception
     */
    protected static function handleSelfAttestation(AttestationObject $attestationObject, string $clientDataHash)
    {
        /** @var CBORByteString $sig */
        $sig = $attestationObject->AttStatement["sig"];

        $publicKey = PublicKeyFactory::Make($attestationObject->AuthData->AttData->CredentialPublicKey);
        $signatureData = $attestationObject->RawAuthData . $clientDataHash;

        if($publicKey->Algorithm !== $attestationObject->AttStatement["alg"]){
            throw new WebAuthnException(
                "Algorithm type mismatch. ".
                "Public Key alg : '".$publicKey->Algorithm."' . ".
                "Attestation Statement alg : '". $attestationObject->AttStatement["alg"] ."'",
                WebAuthnException::ATTESTATION_ALGORITHM_MISMATCH
            );
        }

        if(!$publicKey->Verify($signatureData, $sig->get_byte_string())){
            throw new WebAuthnException(
                "Signature did not verify for self attested packed format",
                WebAuthnException::ATTESTATION_SIGNATURE_INVALID
            );
        }

    }
}