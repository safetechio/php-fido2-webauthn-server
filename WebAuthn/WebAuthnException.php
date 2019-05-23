<?php

namespace SAFETECHio\FIDO2\WebAuthn;

use Exception;

class WebAuthnException extends Exception
{
    const RP_DISPLAY_NAME_NOT_SET = 1;

    const RP_ID_NOT_SET = 2;

    const RP_ID_NOT_VALID_URI = 3;

    const RP_ORIGIN_NOT_VALID_URL = 4;

    /**
     * Override constructor and make message and code mandatory
     * @param string $message
     * @param int $code
     * @param Exception|null $previous
     */
    public function __construct($message, $code, Exception $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}