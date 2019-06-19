<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;


class PublicKeyEllipticCurve extends PublicKeyData
{
    /** @var int $Curve */
    public $Curve;
    
    /** @var string $XCoord */
    Public $XCoord;

    /** @var string $YCoord */
    Public $YCoord;

    /**
     * PublicKeyEllipticCurve constructor.
     * @param array $decodedCBORPubKey
     */
    public function __construct(array $decodedCBORPubKey)
    {
        parent::__construct($decodedCBORPubKey);
        
        $this->Curve = $decodedCBORPubKey[-1];
        $this->XCoord = $decodedCBORPubKey[-2]->get_byte_string();
        $this->YCoord = $decodedCBORPubKey[-3]->get_byte_string();
    }

    public function Verify(string $data, string $signature): bool
    {
        // TODO: Implement Verify() method.
        return false;
    }
}