<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator;

/** See User Verification Requirement Enumeration (https://www.w3.org/TR/webauthn/#userVerificationRequirement) */
class UserVerificationRequirement
{
    // The authenticator should not verify the user for the credential
    const VerificationDiscouraged = "discouraged";

    // User verification is preferred to create/release a credential
    const VerificationPreferred = "preferred"; // DEFAULT

    // User verification is required to create/release a credential
    const VerificationRequired = "required";
}