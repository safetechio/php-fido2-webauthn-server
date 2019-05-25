<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;


/** See https://www.w3.org/TR/webauthn/#iface-authenticatorresponse */
class AuthenticatorResponse
{
    /** @var string $ClientDataJSON */
    public $ClientDataJSON;
}