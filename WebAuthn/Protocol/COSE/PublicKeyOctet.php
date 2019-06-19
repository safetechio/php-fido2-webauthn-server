<?php
/**
 * Created by IntelliJ IDEA.
 * User: samyo
 * Date: 19/06/2019
 * Time: 15:23
 */

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;


use Elliptic\EdDSA;

class PublicKeyOctet extends PublicKeyData
{
    /** @var string $XCoord */
    public $XCoord;

    /**
     * PublicKeyOctet constructor.
     * @param array $decodedCBORPubKey
     */
    public function __construct(array $decodedCBORPubKey)
    {
        parent::__construct($decodedCBORPubKey);

        $this->XCoord = $decodedCBORPubKey[-2]->get_byte_string();
    }

    public function Verify(string $data, string $signature): bool
    {
        $hashAlg = COSE::GetHashAlg($this->Algorithm);
        $dataHash = hash($hashAlg, $data, true);

        $ec = new EdDSA('ed25519');
        $key = $ec->keyFromPublic($this->XCoord);

        return $key->verify($dataHash, $signature);
    }
}