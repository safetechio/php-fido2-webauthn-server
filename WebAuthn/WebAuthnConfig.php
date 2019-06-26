<?php

namespace SAFETECHio\FIDO2\WebAuthn;

use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\AuthenticatorSelection;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\ConveyancePreference;

class WebAuthnConfig
{
    public $RPDisplayName;
    public $RPID;
    public $RPOrigin;
    public $RPIcon;
    public $Timeout = 60000;

    /** @var ConveyancePreference $AttestationPreference */
    public $AttestationPreference;

    /** @var AuthenticatorSelection $AuthenticatorSelection */
    public $AuthenticatorSelection;

    /**
     * WebAuthnConfig constructor.
     * @param string $RPDisplayName
     * @param string $RPID
     * @param string | null $RPOrigin
     * @param string | null $RPIcon
     * @throws WebAuthnException
     */
    public function __construct($RPDisplayName, $RPID, $RPOrigin=null, $RPIcon=null)
    {
        $this->RPDisplayName = $RPDisplayName;
        $this->RPID = $RPID;
        $this->RPOrigin = $RPOrigin;
        $this->RPIcon = $RPIcon;

        $this->validate();
    }

    /**
     * @throws WebAuthnException
     */
    public function validate()
    {
        // Check that the relying party's display name is set
        if(strlen($this->RPDisplayName) == 0)
        {
            throw new WebAuthnException(
                "RPDisplayName not set",
                WebAuthnException::RP_DISPLAY_NAME_NOT_SET
            );
        }

        // Check that the Relying Party's ID is set
        if(strlen($this->RPID) == 0)
        {
            throw new WebAuthnException(
              "RPID not set",
              WebAuthnException::RP_ID_NOT_SET
            );
        }

        // Check that the Timeout value is greater than zero, if not set it to 60000
        if($this->Timeout >! 0)
        {
            $this->Timeout = 60000;
        }

        // Check that the Relying Party's Origin is set, if not, set to the RPID value
        if(strlen($this->RPOrigin) == 0)
        {
            $this->RPOrigin = $this->RPID;
        }

        // If the Relying Party's Orgin is set, check that it is a valid URL
        else
        {
            if (filter_var($this->RPOrigin, FILTER_VALIDATE_URL) === FALSE)
            {
                throw new WebAuthnException(
                    "RPOrigin not a valid URL",
                    WebAuthnException::RP_ORIGIN_NOT_VALID_URL
                );
            }
        }
    }
}