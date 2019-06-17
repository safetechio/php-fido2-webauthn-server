<?php
/**
 * Created by IntelliJ IDEA.
 * User: samyo
 * Date: 14/06/2019
 * Time: 16:28
 */

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers;


use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObject;

interface AttestationFormatHandler
{
    public static function Verify(AttestationObject $attestationObject, string $clientDataHash);

    public static function Name():string;
}