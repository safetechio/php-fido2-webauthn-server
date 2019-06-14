<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation;

use SAFETECHio\FIDO2\Tools\EnumType;

/** @see https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject#Properties */
class AttestationObjectFormat extends EnumType
{
    const ANDROID_KEY = "android-key";
    const ANDROID_SAFETY_NET = "android-safetynet";
    const FIDO_U2F = "fido-u2f";
    const NONE = "none";
    const PACKED = "packed";
    const TPM = "tpm";
}