<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;


/**
 * Class PublicKeyData
 * @package SAFETECHio\FIDO2\WebAuthn\Protocol\COSE
 * @see https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
 */
abstract class PublicKeyData implements PublicKeyInterface
{
    /** @var int $KeyType */
    public $KeyType;

    /** @var int $Algorithm */
    public $Algorithm;

    /** @var array $decodedKey */
    public $DecodedKey;

    /**
     * PublicKeyData constructor.
     * @param array $decodedCBORPubKey
     */
    public function __construct(array $decodedCBORPubKey)
    {
        $this->KeyType = $decodedCBORPubKey[1];
        $this->Algorithm = $decodedCBORPubKey[3];
        $this->DecodedKey = $decodedCBORPubKey;
    }
}