<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;


use CBOR\CBOREncoder;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;

class PublicKeyFactory
{
    /**
     * @param string $publicKeyBytes
     * @return PublicKeyData
     * @throws \Exception
     * @throws WebAuthnException
     */
    public static function Make(string $publicKeyBytes): PublicKeyData
    {
        $decodedPK = CBOREncoder::decode($publicKeyBytes);

        switch ($decodedPK[1]){
            case COSEKeyTypes::OctetKey:
                return new PublicKeyOctet($decodedPK);
                break;
            case COSEKeyTypes::EllipticKey:
                return new PublicKeyEllipticCurve($decodedPK);
                break;
            case COSEKeyTypes::RSAKey:
                return new PublicKeyRSA($decodedPK);
                break;
            default:
                throw new WebAuthnException(
                    "Unknown public key type : " . $decodedPK[1],
                    WebAuthnException::ATTESTATION_UNKNOWN_PUBLIC_KEY_TYPE
                );
                break;
        }
    }
}