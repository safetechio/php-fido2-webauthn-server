<?php
/**
 * Created by IntelliJ IDEA.
 * User: samyo
 * Date: 19/06/2019
 * Time: 15:53
 */

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\COSE;


interface PublicKeyInterface
{
    public function Verify(string $data, string $signature): bool;
}