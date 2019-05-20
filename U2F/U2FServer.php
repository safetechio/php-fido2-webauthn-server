<?php
namespace SAFETECHio\FIDO2\U2F;

use \InvalidArgumentException;
use SAFETECHio\FIDO2\Certificates\Certificate;
use SAFETECHio\FIDO2\Tools\Tools;
use \stdClass;


class U2FServer
{
    /** Constant for the version of the u2f protocol */
    const VERSION = "U2F_V2";

    /** @internal */
    const PUBKEY_LEN = 65;

    /**
     * @throws U2FException If OpenSSL older than 1.0.0 is used
     */
    public static function checkOpenSSLVersion()
    {
        if(OPENSSL_VERSION_NUMBER < 0x10000000) {
            throw new U2FException(
                'OpenSSL has to be at least version 1.0.0, this is ' . OPENSSL_VERSION_TEXT,
                U2FException::OLD_OPENSSL
            );
        }
        return true;
    }

    /**
     * Called to get a registration request to send to a user.
     * Returns an array of one registration request and a array of sign requests.
     *
     * @param string $appId Application id for the running application, Basically the app's URL
     * @param array $registrations List of current registrations for this
     * user, to prevent the user from registering the same authenticator several
     * times.
     * @return array An array of two elements, the first containing a
     * RegisterRequest the second being an array of SignRequest
     * @throws U2FException
     */
    public static function makeRegistration($appId, array $registrations = [])
    {
        $request = new RegistrationRequest(static::createChallenge(), $appId);
        $signatures = static::makeAuthentication($registrations, $appId);
        return [
            "request" => $request,
            "signatures" => $signatures
        ];
    }

    /**
     * Called to verify and unpack a registration message.
     *
     * @param RegistrationRequest $request this is a reply to
     * @param object $response response from a user
     * @param string $attestDir
     * @param bool $includeCert set to true if the attestation certificate should be
     * included in the returned Registration object
     * @return Registration
     * @throws InvalidArgumentException
     * @throws U2FException
     */
    public static function register(RegistrationRequest $request, $response, $attestDir = null, $includeCert = true)
    {
        static::registerValidation($request, $response, $includeCert);

        // Unpack the registration data coming from the client-side token
        $rawRegistration = Tools::base64u_decode($response->registrationData);
        $registrationData = array_values(unpack('C*', $rawRegistration));
        $clientData = Tools::base64u_decode($response->clientData);
        $clientToken = json_decode($clientData);

        // Check Client's challenge matches the original request's challenge
        if($clientToken->challenge !== $request->challenge()) {
            throw new U2FException(
                'Registration challenge does not match',
                U2FException::UNMATCHED_CHALLENGE
            );
        }

        // Begin validating and building the registration
        $registration = new Registration();
        $offset = 1;
        $pubKey = substr($rawRegistration, $offset, static::PUBKEY_LEN);
        $offset += static::PUBKEY_LEN;

        // Validate and set the public key
        if(static::publicKeyToPem($pubKey) === null) {
            throw new U2FException(
                'Decoding of public key failed',
                U2FException::PUBKEY_DECODE
            );
        }
        $registration->publicKey = base64_encode($pubKey);

        // Build and set the key handle.
        $keyHandleLength = $registrationData[$offset++];
        $keyHandle = substr($rawRegistration, $offset, $keyHandleLength);
        $offset += $keyHandleLength;
        $registration->keyHandle = Tools::base64u_encode($keyHandle);

        // Build certificate
        // Set certificate length
        // Note: length of certificate is stored in byte 3 and 4 (excluding the first 4 bytes)
        $certLength = 4;
        $certLength += ($registrationData[$offset + 2] << 8);
        $certLength += $registrationData[$offset + 3];

        // Write the certificate from the returning registration data
        $cert = new Certificate($rawRegistration, $offset, $certLength);
        if($includeCert) {
            $registration->certificate = base64_encode($cert->DER());
        }

        // If we've set the attestDir, check the given certificate can be used.
        if($attestDir) {
            if(openssl_x509_checkpurpose($cert->PEM(), -1, Certificate::getCerts($attestDir)) !== true) {
                throw new U2FException(
                    'Attestation certificate can not be validated',
                    U2FException::ATTESTATION_VERIFICATION
                );
            }
        }

        // Attempt to extract public key from the certificate, if we can't something went wrong in making it.
        if(!openssl_pkey_get_public($cert->PEM())) {
            throw new U2FException(
                'Decoding of public key failed',
                U2FException::PUBKEY_DECODE
            );
        }

        // Generate signature from the remaining part of the raw registration data
        $signature = substr($rawRegistration, $offset);

        // Build a verification string from the components we've made in this function
        $dataToVerify  = chr(0);
        $dataToVerify .= Tools::SHA256($request->appId(), true);
        $dataToVerify .= Tools::SHA256($clientData, true);
        $dataToVerify .= $keyHandle;
        $dataToVerify .= $pubKey;

        // Verify our data against the signature and the certificate, on success return the registration object
        if(openssl_verify($dataToVerify, $signature, $cert->PEM(), 'sha256') === 1) {
            return $registration;
        } else {
            throw new U2FException(
                'Attestation signature does not match',
                U2FException::ATTESTATION_SIGNATURE
            );
        }
    }

    /**
     * Called to validate incoming register data
     *
     * @param RegistrationRequest $request this is a reply to
     * @param object $response response from a user
     * @param bool $includeCert set to true if the attestation certificate should be
     * included in the returned Registration object
     * @throws InvalidArgumentException
     * @throws U2FException
     */
    protected static function registerValidation(RegistrationRequest $request, $response, $includeCert)
    {
        // Parameter Checks
        if( !is_object( $request ) ) {
            throw new InvalidArgumentException('$request of register() method only accepts object.');
        }

        if( !is_object( $response ) ) {
            throw new InvalidArgumentException('$response of register() method only accepts object.');
        }

        if( property_exists( $response, 'errorCode') && $response->errorCode !== 0 ) {
            throw new U2FException(
                'User-agent returned error. Error code: ' . $response->errorCode,
                U2FException::BAD_UA_RETURNING
            );
        }

        if( !is_bool( $includeCert ) ) {
            throw new InvalidArgumentException('$include_cert of register() method only accepts boolean.');
        }
    }

    /**
     * Called to get an authentication request.
     *
     * @param array $registrations An array of the registrations to create authentication requests for.
     * @param string $appId Application id for the running application, Basically the app's URL
     * @return array An array of SignRequest
     * @throws InvalidArgumentException
     * @throws U2FException
     */
    public static function makeAuthentication(array $registrations, $appId)
    {
        $signatures = [];
        foreach ($registrations as $reg) {
            if( !is_object( $reg ) ) {
                throw new InvalidArgumentException('$registrations of makeAuthentication() method only accepts array of object.');
            }

            $signatures[] = new SignRequest([
                'appId' => $appId,
                'keyHandle' => $reg->keyHandle,
                'challenge' => static::createChallenge(),
            ]);
        }
        return $signatures;
    }

    /**
     * Called to verify an authentication response
     *
     * @param array $requests An array of outstanding authentication requests
     * @param array <Registration> $registrations An array of current registrations
     * @param object $response A response from the authenticator
     * @return stdClass
     * @throws U2FException
     *
     * The Registration object returned on success contains an updated counter
     * that should be saved for future authentications.
     * If the Error returned is ERR_COUNTER_TOO_LOW this is an indication of
     * token cloning or similar and appropriate action should be taken.
     */
    public static function authenticate(array $requests, array $registrations, $response)
    {
        // Parameter checks
        if( !is_object( $response ) ) {
            throw new InvalidArgumentException('$response of authenticate() method only accepts object.');
        }

        if( property_exists( $response, 'errorCode') && $response->errorCode !== 0 ) {
            throw new U2FException(
                'User-agent returned error. Error code: ' . $response->errorCode,
                U2FException::BAD_UA_RETURNING
            );
        }

        // Set default values to null, so we get fails by default
        /** @var object|null $req */
        $req = null;

        /** @var object|null $reg */
        $reg = null;

        // Extract client response data
        $clientData = Tools::base64u_decode($response->clientData);
        $decodedClient = json_decode($clientData);

        // Check we have a match among the requests and the response
        foreach ($requests as $req) {
            if( !is_object( $req ) ) {
                throw new InvalidArgumentException('$requests of authenticate() method only accepts an array of objects.');
            }

            if($req->keyHandle() === $response->keyHandle && $req->challenge() === $decodedClient->challenge) {
                break;
            }

            $req = null;
        }
        if($req === null) {
            throw new U2FException(
                'No matching request found',
                U2FException::NO_MATCHING_REQUEST
            );
        }

        // Check for a match for the response among a list of registrations
        foreach ($registrations as $reg) {
            if( !is_object( $reg ) ) {
                throw new InvalidArgumentException('$registrations of authenticate() method only accepts an array of objects.');
            }

            if($reg->keyHandle === $response->keyHandle) {
                break;
            }
            $reg = null;
        }
        if($reg === null) {
            throw new U2FException(
                'No matching registration found',
                U2FException::NO_MATCHING_REGISTRATION
            );
        }

        // On Success, check we have a valid public key
        $pemKey = static::publicKeyToPem(Tools::base64u_decode($reg->publicKey));
        if($pemKey === null) {
            throw new U2FException(
                'Decoding of public key failed',
                U2FException::PUBKEY_DECODE
            );
        }

        // Build signature and data from response
        $signData = Tools::base64u_decode($response->signatureData);
        $dataToVerify  = Tools::SHA256($req->appId(), true);
        $dataToVerify .= substr($signData, 0, 5);
        $dataToVerify .= Tools::SHA256($clientData, true);
        $signature = substr($signData, 5);

        // Verify the response data against the public key
        if(openssl_verify($dataToVerify, $signature, $pemKey, 'sha256') === 1) {
            $ctr = unpack("Nctr", substr($signData, 1, 4));
            $counter = $ctr['ctr'];
            /* TODO: wrap-around should be handled somehow.. */
            if($counter > $reg->counter) {
                $reg->counter = $counter;
                return $reg;
            } else {
                throw new U2FException(
                    'Counter too low.',
                    U2FException::COUNTER_TOO_LOW
                );
            }
        } else {
            throw new U2FException(
                'Authentication failed',
                U2FException::AUTHENTICATION_FAILURE
            );
        }
    }

    /**
     * @param string $key
     * @return null|string
     */
    private static function publicKeyToPem($key)
    {
        if(strlen($key) !== static::PUBKEY_LEN || $key[0] !== "\x04") {
            return null;
        }

        /*
         * Convert the public key to binary DER format first
         * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
         *
         *  SEQUENCE(2 elem)                        30 59
         *   SEQUENCE(2 elem)                       30 13
         *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
         *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
         *   BIT STRING(520 bit)                    03 42 ..key..
         */
        $der  = "\x30\x59";
        $der .= "\x30\x13";
        $der .= "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        $der .= "\x03\x42\0".$key;

        $pem  = "-----BEGIN PUBLIC KEY-----\r\n";
        $pem .= chunk_split(base64_encode($der), 64);
        $pem .= "-----END PUBLIC KEY-----";

        return $pem;
    }

    /**
     * @return string
     * @throws U2FException
     */
    private static function createChallenge()
    {
        $challenge = openssl_random_pseudo_bytes(32, $crypto_strong );
        if( $crypto_strong !== true ) {
            throw new U2FException(
                'Unable to obtain a good source of randomness',
                U2FException::BAD_RANDOM
            );
        }

        $challenge = Tools::base64u_encode( $challenge );

        return $challenge;
    }

}