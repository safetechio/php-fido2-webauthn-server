<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;


use Elliptic\EC;
use FreeDSx\Asn1\Encoders;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\SequenceType;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;

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

    /**
     * @param string $data
     * @param string $signature
     * @return bool
     * @throws WebAuthnException
     * @throws EncoderException
     * @throws PartialPduException
     */
    public function Verify(string $data, string $signature): bool
    {
        var_dump($this->Algorithm);

        switch ($this->Algorithm){
            case COSE::AlgES256:
                $ec = new EC('p256');
                break;
            case COSE::AlgES384:
                $ec = new EC('p384');
                break;
            case COSE::AlgES512:
                $ec = new EC('p512');
                break;
            default:
                throw new WebAuthnException(
                    "Algorithm type not supported for elliptic curve key : ". $this->Algorithm,
                    WebAuthnException::ATTESTATION_UNSUPPORTED_ALGORITHM
                );
        }

        $x = bin2hex($this->XCoord);
        $y = bin2hex($this->YCoord);

        $key = $ec->keyFromPublic("04$x$y", "hex");

        /** @var SequenceType $decodedSig */
        $decodedSig = Encoders::der()->decode($signature);
        $sig = [];
        $sig["r"] = $decodedSig->getChild(0)->getValue();
        $sig["s"] = $decodedSig->getChild(1)->getValue();

        $hashAlg = COSE::GetHashAlg($this->Algorithm);
        $dataHash = hash($hashAlg, $data);

        return $key->verify($dataHash, $sig);
    }
}