<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;


class PublicKeyCredentialRequestOptions
{
    /** @var string $Challenge */
    public $Challenge;

    /** @var int $Timeout */
    public $Timeout;

    /** @var string $RelyingPartyID */
    public $RelyingPartyID;

    /** @var CredentialDescriptor[] $AllowedCredentials */
    public $AllowedCredentials;

    /** @var string $UserVerification */
    public $UserVerification;

    /** @var array $Extensions */
    public $Extensions;

    /**
     * @return array
     */
    public function AllowedCredentialIDs()
    {
        $out = [];
        foreach ($this->AllowedCredentials as $credential)
        {
            $out[] = $credential->CredentialID;
        }

        return $out;
    }
}