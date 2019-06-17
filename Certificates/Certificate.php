<?php

namespace SAFETECHio\FIDO2\Certificates;

use SAFETECHio\FIDO2\Tools\Tools;

class Certificate
{
    protected $derCert;
    protected $pemCert;

    /**
     * Certificates constructor.
     * @param $rawRegistration
     * @param $offset
     * @param $certLength
     */
    public function __construct($rawRegistration, $offset, $certLength)
    {
        $this->derCert = self::makeDERFromReg($rawRegistration, $offset, $certLength);
        $this->pemCert = self::convertDERToPEM($this->derCert);
    }

    /**
     * @return string
     */
    public function DER()
    {
        return $this->derCert;
    }

    /**
     * @return string
     */
    public function PEM()
    {
        return $this->pemCert;
    }

    /**
     * @param $rawRegistration
     * @param $offset
     * @param $certLength
     * @return string
     */
    protected static function makeDERFromReg($rawRegistration, $offset, $certLength)
    {
        $DERBeforeFix = substr($rawRegistration, $offset, $certLength);
        return self::unusedBytesFix($DERBeforeFix);
    }

    /**
     * Fixes a certificate where the signature contains unused bits.
     *
     * @param string $cert
     * @return string
     */
    protected static function unusedBytesFix($cert)
    {
        if(in_array(Tools::SHA256($cert), static::getCertHashes())) {
            $cert[strlen($cert) - 257] = "\0";
        }
        return $cert;
    }

    /**
     * @param $derCert
     * @return string
     */
    public static function convertDERToPEM($derCert)
    {
        $derCert = static::unusedBytesFix($derCert);
        $pemCert = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split(base64_encode($derCert), 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;
        return $pemCert;
    }

    /**
     * @param $certBytes
     * @return array
     */
    public static function ParseCertBytes($certBytes)
    {
        $pem = static::convertDERToPEM($certBytes);
        return openssl_x509_parse($pem);
    }

    /**
     * @return array
     */
    protected static function getCertHashes()
    {
        return [
            '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8',
            'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f',
            '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae',
            'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb',
            '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897',
            'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511'
        ];
    }

    /**
     * @param string $attestDir
     * @return array
     */
    public static function getCerts($attestDir)
    {
        $files = [];
        $dir = $attestDir;
        if($dir && $handle = opendir($dir)) {
            while(false !== ($entry = readdir($handle))) {
                if(is_file("$dir/$entry")) {
                    $files[] = "$dir/$entry";
                }
            }
            closedir($handle);
        }
        return $files;
    }
}