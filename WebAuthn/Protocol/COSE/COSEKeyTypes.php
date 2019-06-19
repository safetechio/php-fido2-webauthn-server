<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;


use SAFETECHio\FIDO2\Tools\EnumType;

class COSEKeyTypes
{
    use EnumType;

    const OctetKey = 1;

    const EllipticKey = 2;

    const RSAKey = 3;
}