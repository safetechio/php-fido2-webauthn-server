<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Entities;

use SAFETECHio\FIDO2\WebAuthn\Contracts\User;

/** See https://www.w3.org/TR/webauthn/#sctn-user-credential-params */
class UserEntity extends CredentialEntity
{
    /** @var string $DisplayName */
    public $DisplayName;

    /** @var string $ID */
    public $ID;

    /**
     * @param User $user
     * @return UserEntity
     */
    public static function FromUser(User $user)
    {
        $u = new static();
        $u->ID = $user->WebAuthnID();
        $u->DisplayName = $user->WebAuthnDisplayName();
        $u->Name = $user->WebAuthnName();
        $u->Icon = $user->WebAuthnIcon();

        return $u;
    }

    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        $json["id"] = $this->ID;

        if(strlen($this->DisplayName) > 0){
            $json["displayName"] = $this->DisplayName;
        }

        return $json;
    }
}