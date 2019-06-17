<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;

use SAFETECHio\FIDO2\Tools\EnumType;

class COSE
{
    use EnumType;

    // AlgES256 ECDSA with SHA-256
    const AlgES256 = -7;

    // AlgES384 ECDSA with SHA-384
    const AlgES384 = -35;

    // AlgES512 ECDSA with SHA-512
    const AlgES512 = -36;

    // AlgRS1 RSASSA-PKCS1-v1_5 with SHA-1
    const AlgRS1 = -65535;

    // AlgRS256 RSASSA-PKCS1-v1_5 with SHA-256
    const AlgRS256 = -257;

    // AlgRS384 RSASSA-PKCS1-v1_5 with SHA-384
    const AlgRS384 = -258;

    // AlgRS512 RSASSA-PKCS1-v1_5 with SHA-512
    const AlgRS512 = -259;

    // AlgPS256 RSASSA-PSS with SHA-256
    const AlgPS256 = -37;

    // AlgPS384 RSASSA-PSS with SHA-384
    const AlgPS384 = -38;

    // AlgPS512 RSASSA-PSS with SHA-512
    const AlgPS512 = -39;

    // AlgEdDSA EdDSA
    const AlgEdDSA = -8;

    protected static $hashToAlg = [
        COSE::AlgES256 => ["sha256", OPENSSL_ALGO_SHA256],
        COSE::AlgES384 => ["sha384", OPENSSL_ALGO_SHA384],
        COSE::AlgES512 => ["sha512", OPENSSL_ALGO_SHA512],
        COSE::AlgRS1   => ["sha1", OPENSSL_ALGO_SHA1],
        COSE::AlgRS256 => ["sha256", OPENSSL_ALGO_SHA256],
        COSE::AlgRS384 => ["sha384", OPENSSL_ALGO_SHA384],
        COSE::AlgRS512 => ["sha512", OPENSSL_ALGO_SHA512],
        COSE::AlgPS256 => ["sha256", OPENSSL_ALGO_SHA256],
        COSE::AlgPS384 => ["sha384", OPENSSL_ALGO_SHA384],
        COSE::AlgPS512 => ["sha512", OPENSSL_ALGO_SHA512],
        COSE::AlgEdDSA => ["sha512", OPENSSL_ALGO_SHA512],
    ];

    /**
     * @param int $COSEValue
     * @return string hash algorithm
     */
    public static function GetHashAlg(int $COSEValue): string
    {
        return static::$hashToAlg[$COSEValue][0];
    }

    public static function GetOpenSSLHashAlg(int $COSEValue): int
    {
        return static::$hashToAlg[$COSEValue][1];
    }
}