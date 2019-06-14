<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Client;


use SAFETECHio\FIDO2\Tools\EnumType;

class CeremonyType extends EnumType
{
    const CREATE = "webauthn.create";
    const GET = "webauthn.get";
}