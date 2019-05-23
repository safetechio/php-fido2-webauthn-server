<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;

/** See Platform Attachment https://www.w3.org/TR/webauthn/#platform-attachment */
class AuthenticatorAttachment
{
    const CROSS_PLATFORM = "cross-platform";
    const PLATFORM = "platform";
}
