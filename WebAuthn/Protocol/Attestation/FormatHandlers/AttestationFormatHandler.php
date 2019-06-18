<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers;


use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObject;

interface AttestationFormatHandler
{
    public static function Verify(AttestationObject $attestationObject, string $clientDataHash);

    public static function Name():string;
}