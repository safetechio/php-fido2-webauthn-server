<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Options;


class AuthenticationExtension implements \JsonSerializable
{
    /** @var string $name */
    protected $name;

    /** @var string $value */
    protected $value;

    /**
     * AuthenticationExtension constructor.
     * @param string $name
     * @param string $value
     */
    public function __construct(string $name, string $value)
    {
        $this->name = $name;
        $this->value = $value;
    }

    /** @return string */
    public function name(): string
    {
        return $this->name;
    }

    /** @return string */
    public function value()
    {
        return $this->value;
    }

    public function jsonSerialize()
    {
        return $this->value;
    }
}