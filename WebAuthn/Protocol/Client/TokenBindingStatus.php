<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Client;


use SAFETECHio\FIDO2\Tools\EnumType;

class TokenBindingStatus extends EnumType
{
    const Present = "present";
    const Supported = "supported";
    const NotSupported = "not-supported";
}