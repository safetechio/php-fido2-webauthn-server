<?php

namespace SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation;

use CBOR\CBOREncoder;
use CBOR\Types\CBORByteString;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\AuthenticatorData;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Authenticator\AuthenticatorResponse;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Client\CollectedClientData;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Client\TokenBinding;

class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    /** @var AttestationObject $AttestationObject */
    public $AttestationObject;

    /**
     * @throws \Exception
     */
    public function Parse(): ParsedAttestationResponse
    {
        $out = new ParsedAttestationResponse();

        $out->CollectedClientData = $this->parseClientData();
        $out->AttestationObject = $this->parseAttestationObject();

        return $out;
    }

    protected function parseClientData(): CollectedClientData
    {
        $ccd = new CollectedClientData();

        $clientData = Tools::base64u_decode($this->ClientDataJSON);
        $clientDataJson = json_decode($clientData, true);

        $ccd->Type = $clientDataJson["type"];
        $ccd->Challenge = $clientDataJson["challenge"];
        $ccd->Origin = $clientDataJson["origin"];

        if(isset($clientDataJson["hint"])){
            $ccd->Hint = $clientDataJson["hint"];
        }

        if(isset($clientDataJson["tokenBinding"])){
            $tb = new TokenBinding();
            $tb->ID = $clientDataJson["tokenBinding"]["id"];
            $tb->Status = $clientDataJson["tokenBinding"]["status"];

            $ccd->TokenBinding = $tb;
        }

        return $ccd;
    }

    /**
     * @throws \Exception
     */
    protected function parseAttestationObject(): AttestationObject
    {
        $out = new AttestationObject();

        $base64Decode = Tools::base64u_decode($this->AttestationObject);
        $decodedAttestationObject = CBOREncoder::decode($base64Decode);

        /** @var CBORByteString $decodedAttestationObject["authData"] */
        $out->RawAuthData = $decodedAttestationObject["authData"]->get_byte_string();
        $out->Format = $decodedAttestationObject["fmt"];
        $out->AttStatement = $decodedAttestationObject["attStmt"];
        $out->AuthData = AuthenticatorData::ParseRawAuthData($out->RawAuthData);

        //TODO
        return $out;
    }
}