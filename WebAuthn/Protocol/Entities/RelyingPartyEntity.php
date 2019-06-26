<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Entities;

use SAFETECHio\FIDO2\WebAuthn\WebAuthnConfig;

/** See https://www.w3.org/TR/webauthn/#sctn-rp-credential-params */
class RelyingPartyEntity extends CredentialEntity
{
    /** @var string $ID */
    public $ID;

    /**
     * @param WebAuthnConfig $config
     * @return RelyingPartyEntity
     */
    public static function FromConfig(WebAuthnConfig $config)
    {
        $rp = new static();
        $rp->ID = $config->RPID;
        $rp->Name = $config->RPDisplayName;
        $rp->Icon = $config->RPIcon;

        return $rp;
    }

    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        $json["id"] = $this->ID;

        return $json;
    }
}