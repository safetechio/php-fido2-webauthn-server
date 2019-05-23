<?php

namespace SAFETECHio\FIDO2\Exceptions;

use Exception;

class FIDO2Exception extends Exception
{
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