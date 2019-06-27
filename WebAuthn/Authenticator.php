<?php

namespace SAFETECHio\FIDO2\WebAuthn;


use SAFETECHio\FIDO2\Tools\Tools;

class Authenticator implements \JsonSerializable
{
    /** @var string $AAGUID */
    public $AAGUID;

    /** @var int $SignCount */
    public $SignCount;

    /** @var boolean $CloneWarning */
    public $CloneWarning;

    /**
     * Authenticator constructor.
     * @param string $aaguid
     * @param int $count
     */
    public function __construct(string $aaguid, int $count)
    {
        $this->AAGUID = $aaguid;
        $this->SignCount = $count;
    }

    /**
     * @param int $count
     */
    public function UpdateCounter(int $count)
    {
        if ($count <= $this->SignCount && $count != 0) {
            $this->CloneWarning = true;
	    }
        $this->SignCount = $count;
    }

    public function jsonSerialize()
    {
        return [
            "AAGUID" => Tools::base64u_encode($this->AAGUID),
            "SignCount" => $this->SignCount,
        ];
    }
}