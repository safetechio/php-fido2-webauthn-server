<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;

/** see https://www.w3.org/TR/webauthn/#authenticatorSelection */
class AuthenticatorSelection implements \JsonSerializable
{
    /**
     * AuthenticatorAttachment
     * If this property is present, eligible authenticators are filtered to only
     * authenticators attached with the specified AuthenticatorAttachment enum
     *
     * See Platform Attachment https://www.w3.org/TR/webauthn/#platform-attachment
     *
     * `platform` or `cross-platform`
     *
     * @var string $AuthenticatorAttachment
     */
    public $AuthenticatorAttachment;

    /**
     * RequireResidentKey
     * This property describes the Relying Party's requirements regarding resident
     * credentials. If the parameter is set to true, the authenticator MUST create a client-side-resident
     * public key credential source when creating a public key credential.
     *
     * @var boolean $RequireResidentKey
     */
    public $RequireResidentKey;

    /**
     * UserVerification
     * This property describes the Relying Party's requirements regarding user verification for
     * the create() operation. Eligible authenticators are filtered to only those capable of satisfying this
     * requirement.
     *
     * See User Verification Requirement Enumeration https://www.w3.org/TR/webauthn/#userVerificationRequirement
     *
     * `required`, `preferred` or `discouraged`
     *
     * @var string $UserVerification
     */
    public $UserVerification;

    /**
     * AuthenticatorSelection constructor.
     * @param boolean $RequireResidentKey
     * @param string $UserVerification
     * @param string | null $AuthenticatorAttachment
     */
    public function __construct($RequireResidentKey, $UserVerification, $AuthenticatorAttachment=null)
    {
        $this->RequireResidentKey = $RequireResidentKey;
        $this->UserVerification = $UserVerification;
        $this->AuthenticatorAttachment = $AuthenticatorAttachment;
    }

    public function jsonSerialize()
    {
        $json = [];

        if(strlen($this->AuthenticatorAttachment) > 0){
            $json["authenticatorAttachment"] = $this->AuthenticatorAttachment;
        }

        if($this->RequireResidentKey === null){
            $json["requireResidentKey"] = $this->RequireResidentKey;
        }

        if(strlen($this->UserVerification) > 0){
            $json["userVerification"] = $this->UserVerification;
        }

        return $json;
    }
}