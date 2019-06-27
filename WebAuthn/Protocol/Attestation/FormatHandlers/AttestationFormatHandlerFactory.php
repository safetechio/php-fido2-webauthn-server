<?php
/**
 * Created by IntelliJ IDEA.
 * User: samyo
 * Date: 27/06/2019
 * Time: 17:53
 */

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AttestationObjectFormat;

/**
 * Class AttestationFormatHandlerFactory
 * @package SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers
 */
class AttestationFormatHandlerFactory
{
    /**
     * @param string $formatType
     * @return AttestationFormatHandler
     * @throws \Exception
     */
    public static function Make(string $formatType): AttestationFormatHandler
    {
        // TODO add additional attestation format handling
        switch ($formatType){
            case AttestationObjectFormat::PACKED:
                return new PackedAttestation();
                break;
            case AttestationObjectFormat::FIDO_U2F:
                return new FidoU2FAttestation();
                break;
            default:
                throw new \Exception("Attestation format not yet supported : " . $formatType);
        }
    }
}