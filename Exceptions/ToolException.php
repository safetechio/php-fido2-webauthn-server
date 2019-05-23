<?php

namespace SAFETECHio\FIDO2\Exceptions;

class ToolException extends FIDO2Exception
{
    /** Error for not getting good random from the system */
    const BAD_RANDOM = 1;
}