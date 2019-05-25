<?php

namespace SAFETECHio\FIDO2\Exceptions;

class WebAuthnException extends FIDO2Exception
{
    const RP_DISPLAY_NAME_NOT_SET = 1;

    const RP_ID_NOT_SET = 2;

    const RP_ID_NOT_VALID_URI = 3;

    const RP_ORIGIN_NOT_VALID_URL = 4;

    const ID_MISMATCH = 5;

    const HASH_MISMATCH = 6;
}