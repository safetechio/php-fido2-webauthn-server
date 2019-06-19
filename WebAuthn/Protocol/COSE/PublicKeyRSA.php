<?php
/**
 * Created by IntelliJ IDEA.
 * User: samyo
 * Date: 19/06/2019
 * Time: 15:18
 */

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;


class PublicKeyRSA extends PublicKeyData
{
    /** @var string $Modulus */
    public $Modulus;

    /** @var string $Exponent */
    public $Exponent;

    /**
     * PublicKeyRSA constructor.
     * @param array $decodedCBORPubKey
     */
    public function __construct(array $decodedCBORPubKey)
    {
        parent::__construct($decodedCBORPubKey);

        $this->Modulus = $decodedCBORPubKey[-1]->get_byte_string();
        $this->Exponent = $decodedCBORPubKey[-2]->get_byte_string();
    }

    public function Verify(string $data, string $signature): bool
    {
        // TODO: Implement Verify() method.
        return false;
    }
}