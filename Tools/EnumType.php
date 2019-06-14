<?php

namespace SAFETECHio\FIDO2\Tools;

abstract class EnumType
{
    /**
     * @return array
     * @throws \ReflectionException
     */
    public static function All()
    {
        $tbs = new static;
        $reflectionClass = new \ReflectionClass($tbs);
        return $reflectionClass->getConstants();
    }
}