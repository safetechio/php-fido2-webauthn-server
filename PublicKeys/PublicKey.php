<?php

namespace SAFETECHio\FIDO2\PublicKeys;

class PublicKey
{
    const PUBKEY_LEN = 65;

    protected $publicKey;

    /**
     * PublicKey constructor.
     * @param $publicKey
     */
    protected function __construct($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * @param $rawRegistration
     * @param $offset
     * @return PublicKey
     */
    public static function fromRegistration($rawRegistration, $offset)
    {
        return new static(substr($rawRegistration, $offset, static::PUBKEY_LEN));
    }

    /**
     * @param $privateKeyString
     * @return PublicKey
     */
    public static function fromString($privateKeyString)
    {
        return new static($privateKeyString);
    }

    /**
     * @return null|string
     */
    public function toPEM()
    {
        if(strlen($this->publicKey) !== static::PUBKEY_LEN || $this->publicKey[0] !== "\x04") {
            return null;
        }

        /*
         * Convert the public key to binary DER format first
         * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
         *
         *  SEQUENCE(2 elem)                        30 59
         *   SEQUENCE(2 elem)                       30 13
         *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
         *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
         *   BIT STRING(520 bit)                    03 42 ..key..
         */
        $der  = "\x30\x59";
        $der .= "\x30\x13";
        $der .= "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        $der .= "\x03\x42\0".$this->publicKey;

        $pem  = "-----BEGIN PUBLIC KEY-----\r\n";
        $pem .= chunk_split(base64_encode($der), 64);
        $pem .= "-----END PUBLIC KEY-----";

        return $pem;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->publicKey;
    }
}