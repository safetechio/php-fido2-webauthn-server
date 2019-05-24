<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;

/** See Authenticator Transport https://www.w3.org/TR/webauthn/#transport */
class AuthenticatorTransport
{
    // The authenticator should transport information over USB
    const USB = "usb";

    // The authenticator should transport information over Near Field Communication Protocol
    const NFC = "nfc";

    // The authenticator should transport information over Bluetooth
    const BLE = "ble";

    // The client should use an internal source like a TPM or SE
    const Internal = "internal";
}