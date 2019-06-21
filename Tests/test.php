<?php
require_once "../vendor/autoload.php";

ini_set('xdebug.var_display_max_depth', '10');
ini_set('xdebug.var_display_max_children', '256');
ini_set('xdebug.var_display_max_data', '4096');

use SAFETECHio\FIDO2\Certificates\Certificate;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AuthenticatorAttestationResponse;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers\PackedAttestation;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\ParsedAttestationResponse;

$registrationResponseJSON = '{
	"id":"MntW5QHrnIy_AGAothSeRcYMWd1Z7MgWOEaUALWlDVPl0STqOBgNAyYb-JCSxDebIJAQAoIC64ph7JsbGe7UWg",
	"rawId":"MntW5QHrnIy_AGAothSeRcYMWd1Z7MgWOEaUALWlDVPl0STqOBgNAyYb-JCSxDebIJAQAoIC64ph7JsbGe7UWg",
	"type":"public-key",
	"response":{
		"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgcUsZ2P5x-m_GHPz7RBgvyLC1HNNHtWy2Ra4zElLhCl4CIEij349Mke_G-B_ILf8UGc6U1RdJIEuwlY-bMEZGOS_6Y3g1Y4FZAsEwggK9MIIBpaADAgECAgQq52JjMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBuMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMScwJQYDVQQDDB5ZdWJpY28gVTJGIEVFIFNlcmlhbCA3MTk4MDcwNzUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqA4ZeYEPZnhH_EKolVFeEvwmvjmseOzIXKSFvVRIajNkQ05ndx2i9_kp7x-PavGLm0kaf9Wdbj_qJDMp0hp4_o2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBBtRLqb9uwuSbkwDI_pIMtzMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHJX0Dzcw-EVaYSQ1vgO-VtTByNz2eZHMmMrEdzcd4rsa9WSbQfhe5xUMHiN4y9OR7RYdv-MVSICm-k4eHlXIzHnJ3AWgopxGznHT9bBJYvR5NnlZtVweQNH2lI1wD8P_kCxQo4FxukXmeR1VHFpAe64i7BXiTWIrYiq0w1xTy8vrDbVTbrXEJxbAnqwyrjPNU7xAIoJCGyghpavDPzbwYOY_N8CMWwmIsle5iK90cAKR4nkocy3SaNUul8nYEIwvv-uBua_AvvAFbzRUd811wqYqOQtykSI_PBxBCGI3-odX3S36niLKvnFFKm6uU_nOJzaGVGQsrEwfb-RGOGpKfhoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAABNtRLqb9uwuSbkwDI_pIMtzAEAye1blAeucjL8AYCi2FJ5FxgxZ3VnsyBY4RpQAtaUNU-XRJOo4GA0DJhv4kJLEN5sgkBACggLrimHsmxsZ7tRapQECAyYgASFYIGhP2AUtUrs39wASsPlF8VYO1cJ4Qi5rLJ7AMExGFp8SIlggj7Z7WJnXU-Q6H9oQSM-U62g7xEVcqHKixwbo_KdAN7A",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI4RS1EZDRKQk1RS25kaVhvLWhYZHRqTFdQMEx5bVZaOTFNX2JCWFhydmhRIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
	}
}';

$selfAttestedRSAResponseJSON = '{
    "id": "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
    "rawId": "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
    "response": {
        "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzn__mNzaWdZAQCPypMLXWqtCZ1sc5QdjhH-pAzm8-adpfbemd5zsym2krscwV0EeOdTrdUOdy3hWj5HuK9dIX_OpNro2jKrHfUj_0Kp-u87iqJ3MPzs-D9zXOqkbWqcY94Zh52wrPwhGfJ8BiQp5T4Q97E042hYQRDKmtv7N-BT6dywiuFHxfm1sDbUZ_yyEIN3jgttJzjp_wvk_RJmb78bLPTlym83Y0Ws73K6FFeiqFNqLA_8a4V0I088hs_IEPlj8PWxW0wnIUhI9IcRf0GEmUwTBpbNDGpIFGOudnl_C3YuXuzK3R6pv2r7m9-9cIIeeYXD9BhSMBQ0A8oxBbVF7j-0xXDNrXHZaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAOKjVmSRjt0nqud40p1PeHgEAIB-l9gZ544Ds7vzo_O76UZ8DCXiWFc8DN8LWNZYQH0NepAEDAzn__iBZAQDAIqzybPPmgeL5OR6JKq9bWDiENJlN_LePQEnf1_sgOm4FJ9kBTbOTtWplfoMXg40A7meMppiRqP72A3tmILwZ5xKIyY7V8Y2t8X1ilYJol2nCKOpAEqGLTRJjF64GQxen0uFpi1tA6l6N-ZboPxjky4aidBdUP22YZuEPCO8-9ZTha8qwvTgZwMHhZ40TUPEJGGWOnHNlYmqnfFfk0P-UOZokI0rqtqqQGMwzV2RrH2kjKTZGfyskAQnrqf9PoJkye4KUjWkWnZzhkZbrDoLyTEX2oWvTTflnR5tAVMQch4UGgEHSZ00G5SFoc19nGx_UJcqezx5cLZsny-qQYDRjIUMBAAE",
        "clientDataJSON": "eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjaGFsbGVuZ2UiOiJBWGtYV1hQUDNnTHg4T0xscGtKM2FSUmhGV250blNFTmdnbmpEcEJxbDFuZ0tvbDd4V3dldlVZdnJwQkRQM0xFdmRyMkVPU3RPRnBHR3huTXZYay1WdyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
    },
    "type": "public-key"
}';

$registrationResponse = json_decode($selfAttestedRSAResponseJSON, true);
var_dump($registrationResponse);

$aar = new AuthenticatorAttestationResponse($registrationResponse["response"]);
var_dump($aar);

try{
    $par = new ParsedAttestationResponse($aar);
    var_dump($par);

    $JSONHashRaw = Tools::SHA256(base64_decode($aar->ClientDataJSON), true);
    var_dump($JSONHashRaw);

    PackedAttestation::Verify($par->AttestationObject, $JSONHashRaw);
} catch (Throwable $exception) {
    var_dump($exception);
}