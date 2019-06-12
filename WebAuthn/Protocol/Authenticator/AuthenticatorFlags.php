<?php
/**
 * Created by IntelliJ IDEA.
 * User: samyo
 * Date: 12/06/2019
 * Time: 17:39
 */

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;


/** See flags section of https://www.w3.org/TR/webauthn/#table-authData */
class AuthenticatorFlags
{
    const UserPresent = 1;

    // const reserved = 2;

    const UserVerified = 4;

    // const reserved = 8;

    // const reserved = 16;

    // const reserved = 32;

    const AttestedCredentialData = 64;

    const HasExtensions = 128;

    /** @var string $value */
    protected $value;

    /**
     * AuthenticatorFlags constructor.
     * @param string $flags representing a byte
     */
    public function __construct($flags)
    {
        $this->value = unpack("C", $flags)[1];
    }

    /**
     * UserPresent returns if the UP flag was set
     * @return bool
     */
    public function UserPresent()
    {
        return ($this->value & static::UserPresent) == static::UserPresent;
    }

    /**
     * UserVerified returns if the UV flag was set
     * @return bool
     */
    public function UserVerified()
    {
        return ($this->value & static::UserVerified) == static::UserVerified;
    }

    /**
     * HasAttestedCredentialData returns if the AT flag was set
     * @return bool
     */
    public function HasAttestedCredentialData()
    {
        return ($this->value & static::AttestedCredentialData) == static::AttestedCredentialData;
    }

    /**
     * HasExtensions returns if the ED flag was set
     * @return bool
     */
    public function HasExtensions() {
        return ($this->value & static::HasExtensions) == static::HasExtensions;
    }
}