<?php

namespace SAFETECHio\FIDO2\WebAuthn;


use SAFETECHio\FIDO2\Exceptions\ToolException;
use SAFETECHio\FIDO2\Exceptions\WebAuthnException;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Contracts\User;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\CredentialAssertion;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\CredentialDescriptor;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Options\PublicKeyCredentialRequestOptions;

class WebAuthnBeginAuthentication
{
    /** @var WebAuthnConfig $config */
    protected $config;

    /** @var User $user */
    protected $user;

    /** @var PublicKeyCredentialRequestOptions $creationOptions */
    protected $requestOptions;

    /**
     * WebAuthnBeginAuthentication constructor.
     * @param User $user
     * @param WebAuthnConfig $config
     * @throws ToolException
     * @throws WebAuthnException
     */
    public function __construct(User $user, WebAuthnConfig $config)
    {
        $this->user = $user;

        $this->config = $config;

        $challenge = Tools::createChallenge();

        $credentials = $user->WebAuthnCredentials();
        if(count($credentials) >! 0){
            throw new WebAuthnException(
                "User does not have any credentials",
                WebAuthnException::USER_NO_CREDENTIALS_FOUND
            );
        }

        // TODO move PublicKeyCredentialRequestOptions init code into constructor.
        $requestOptions = new PublicKeyCredentialRequestOptions();
        $requestOptions->Challenge = $challenge;
        $requestOptions->Timeout = $config->Timeout;
        $requestOptions->RelyingPartyID = $config->RPID;
        $requestOptions->UserVerification = $config->AuthenticatorSelection->UserVerification;
        $requestOptions->AllowedCredentials = $user->WebAuthnAllowedCredentials();

        $this->requestOptions = $requestOptions;
    }

    /**
     * @return array
     */
    public function Make()
    {
        $response = new CredentialAssertion($this->requestOptions);

        $newSessionData = new SessionData;
        $newSessionData->Challenge = Tools::base64u_encode($this->requestOptions->Challenge);
        $newSessionData->UserID = $this->user->WebAuthnID();
        $newSessionData->AllowedCredentialIDs = $this->requestOptions->AllowedCredentialIDs();
        $newSessionData->UserVerification = $this->requestOptions->UserVerification;

        return [$response, $newSessionData];
    }
}