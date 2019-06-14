<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Client;


use SAFETECHio\FIDO2\Tools\EnumType;

class CeremonyType
{
    use EnumType;

    const CREATE = "webauthn.create";
    const GET = "webauthn.get";
}