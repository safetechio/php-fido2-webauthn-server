<?php
require_once "../vendor/autoload.php";

ini_set('xdebug.var_display_max_depth', '10');
ini_set('xdebug.var_display_max_children', '256');
ini_set('xdebug.var_display_max_data', '4096');

use SAFETECHio\FIDO2\Certificates\Certificate;
use SAFETECHio\FIDO2\Tools\Tools;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AuthenticatorAttestationResponse;
use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\FormatHandlers\FidoU2FAttestation;
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

$fidoU2FResponseJSON = '{
    "id":"dzTIpxYHcLwtLewbpTe6ozMFp_s4CFs7QhwUXZ6gcV_7yCdP77q2aoyQZaPZHrHlCvv5SVC1EB79eE6C8sjPjg",
    "rawId":"dzTIpxYHcLwtLewbpTe6ozMFp_s4CFs7QhwUXZ6gcV_7yCdP77q2aoyQZaPZHrHlCvv5SVC1EB79eE6C8sjPjg",
    "type":"public-key",
    "response":{
        "attestationObject":"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgLVrfSLDWq_MSspaNrpSEypxLz6jbjHc_l1edQEv0U2ECIQCP80TTI_IZFpYYYZEyOfqFphYAJjKAHTHonKtpenPT42N4NWOBWQJIMIICRDCCAS6gAwIBAgIEeMDfDjALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDIwMjU5MDU5MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS1uHFcg_3-DqFcRXeshY30jBdv3oedyvS4PUDTIPJvreYl_Pf1yK_YNRj4254h7Ag7GEWAxxfsSkcLlopvuj9vozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDALBgkqhkiG9w0BAQsDggEBAD72q_ZKkWsL-ZSTjdyVNOBUQAJoVninLEOnq-ZdkGX_YfRRzoo67thmidGQuVCvAHpU0THu8G_ia06nuz4yt5IFpd-nYAQ0U-NK-ETDfNSoX4xcLYcOCiiyt-1EAkH9s3krIHaw4Yr6m0Mu7vwmWLoJBcQbJKk8bsi7ptVvM-jWU9fPa9UBVFWiZZdA99zFHMAxYJzQPqbN6Tmeygh2MpB2P7TI0A9WkGmhJUkAauuwaiGiFOSZmDe0KegdflbTOlSS3ToWHIKTlUCBqn7vdJw6Vj2919ujlcxHPkRpbUGRhcJDesg6wGTBy-RyJ_96G3fH1eoMNn1F9jC9mY1Zsm5oYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEB3NMinFgdwvC0t7BulN7qjMwWn-zgIWztCHBRdnqBxX_vIJ0_vurZqjJBlo9keseUK-_lJULUQHv14ToLyyM-OpQECAyYgASFYIO0XU8KKUEAc7VRL0wtIQT34rMKsFQD_RnLcaACMtbvPIlggKcKPQ0_ATnZIg7MWXzbJJInK6GQVXgxhuElJ74vJypo",
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJUVUZVU0VzeloycG9aV05YU1hGaE1XeGxiWEJGUm1aMVZrZHdlbU5NUW1kdU1tWkRja1pEZVZvelNRIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgyIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
    }
}';

$RSAAssertion = '{
    "id":"L0qQcYTuFxXrKxloJ6LlE80BSAjBTk1jQEIPDvF-jOg",
    "rawId":"L0qQcYTuFxXrKxloJ6LlE80BSAjBTk1jQEIPDvF-jOg",
    "response":{
        "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAGA",
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJUekYyVmxod1pGbDBWbkl4TUZKTE5rNHlTRU5MUVZSck1FRnlRbUkzTlhrMlpuSnlOWFZVY2tNNVFRIiwiZXh0cmFfa2V5c19tYXlfYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MiIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ"
        "signature":"XUVi7FqGhGZ5r9VmpcmF-FXSuc59BrqoC1Zahh3qopyFC7_PN8bdhK_QRLjghbiuLfPYAH-Cg8NLsEzjiWhp3ue5J-lzSD6BbHKsWw70YVncd4uhQMrIx2dw3Rm-VRYn4gEl4yOIa-Rk8sP0VyB6FKdqikXZOirkZdCiNHU_68nWT0v0qSD_0s0FU08JoNNnb5nkGeX3PiSahdqM8iQUxUZGqjQjEkYGAJTlKxtM7F_d-Nm_9H3axVBQzLk1hGY_RE-0e2g0YZf2ZieKQ1Dk5xjrRpgOyVI9RoSpSVty5Une-mp62SvmR5d7uV5RudAM4Gyj6NiprMEMwHGNgXAKMg"
    "userHandle":"MWU4NGEwZmEtOTk5Ny0xMWU5LWJhN2ItMDI0MmFjMTQwMDAy",
    "type":"public-key"
}';

$registrationResponse = json_decode($fidoU2FResponseJSON, true);
var_dump($registrationResponse);

$aar = new AuthenticatorAttestationResponse($registrationResponse["response"]);
var_dump($aar);

try{
    $par = new ParsedAttestationResponse($aar);
    var_dump($par);

    $JSONHashRaw = Tools::SHA256(base64_decode($aar->ClientDataJSON), true);
    var_dump($JSONHashRaw);

    //PackedAttestation::Verify($par->AttestationObject, $JSONHashRaw);
    FidoU2FAttestation::Verify($par->AttestationObject, $JSONHashRaw);

} catch (Throwable $exception) {
    var_dump($exception);
}