<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;

use ArrayIterator;

/** See https://www.w3.org/TR/webauthn/#dictdef-authenticationextensionsclientinputs */
class AuthenticationExtensionsClientInputs implements \Countable, \IteratorAggregate, \JsonSerializable
{
    /** @var AuthenticationExtension[] $extensions */
    protected $extensions = [];

    /**
     * AuthenticationExtensionsClientInputs constructor.
     * @param AuthenticationExtension[] $extensions
     */
    public function __construct(array $extensions)
    {
        foreach($extensions as $extension)
        {
            $this->extensions[$extension->name()] = $extension;
        }
    }

    /**
     * @param AuthenticationExtension $extension
     */
    public function add(AuthenticationExtension $extension)
    {
        $this->extensions[$extension->name()] = $extension;
    }

    /**
     * @return ArrayIterator
     */
    public function getIterator()
    {
        return new ArrayIterator($this->extensions);
    }

    /**
     * @param int $mode
     * @return int
     */
    public function count($mode = COUNT_NORMAL): int
    {
        return count($this->extensions, $mode);
    }

    public function jsonSerialize()
    {
        return $this->extensions;
    }
}