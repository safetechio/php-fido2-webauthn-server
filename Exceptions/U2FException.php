<?php

namespace SAFETECHio\FIDO2\Exceptions;

class U2FException extends FIDO2Exception
{
    /** Error for the authentication message not matching any outstanding
     * authentication request */
    const NO_MATCHING_REQUEST = 1;

    /** Error for the authentication message not matching any registration */
    const NO_MATCHING_REGISTRATION = 2;

    /** Error for the signature on the authentication message not verifying with
     * the correct key */
    const AUTHENTICATION_FAILURE = 3;

    /** Error for the challenge in the registration message not matching the
     * registration challenge */
    const UNMATCHED_CHALLENGE = 4;

    /** Error for the attestation signature on the registration message not
     * verifying */
    const ATTESTATION_SIGNATURE = 5;

    /** Error for the attestation verification not verifying */
    const ATTESTATION_VERIFICATION = 6;

    /** Error when the counter is lower than expected */
    const COUNTER_TOO_LOW = 7;

    /** Error decoding public key */
    const PUBKEY_DECODE = 8;

    /** Error user-agent returned error */
    const BAD_UA_RETURNING = 9;

    /** Error old OpenSSL version */
    const OLD_OPENSSL = 10;
}