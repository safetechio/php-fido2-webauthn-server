<?php
namespace SAFETECHio\FIDO2\U2F;


class Registration
{
    /** The key handle of the registered authenticator */
    public $keyHandle;

    /** The public key of the registered authenticator */
    public $publicKey;

    /** The attestation certificate of the registered authenticator */
    public $certificate;

    /** The counter associated with this registration */
    protected $counter = -1;

    /**
     * @return string
     */
    public function getCounter()
    {
        return $this->counter;
    }
}