<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;

use SAFETECHio\FIDO2\WebAuthn\Protocol\COSE\COSE;

class CredentialParameter
{
    /** @var integer $Algorithm */
    public $Algorithm;

    /** @var string $Type */
    public $Type;

    /**
     * CredentialParameter constructor.
     * @param $type
     * @param $algorithm
     */
    public function __construct($algorithm, $type="public-key")
    {
        $this->Algorithm = $algorithm;
        $this->Type = $type;
    }

    /**
     * @return CredentialParameter[]
     */
    public static function All()
    {
        return[
            new static(COSE::AlgES256),
            new static(COSE::AlgES384),
            new static(COSE::AlgES512),
            new static(COSE::AlgRS256),
            new static(COSE::AlgRS384),
            new static(COSE::AlgRS512),
            new static(COSE::AlgPS256),
            new static(COSE::AlgPS384),
            new static(COSE::AlgPS512),
            new static(COSE::AlgEdDSA),
        ];
    }
}