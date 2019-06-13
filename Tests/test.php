<?php
require_once "../vendor/autoload.php";

ini_set('xdebug.var_display_max_depth', '10');
ini_set('xdebug.var_display_max_children', '256');
ini_set('xdebug.var_display_max_data', '4096');

use SAFETECHio\FIDO2\WebAuthn\Protocol\Attestation\AuthenticatorAttestationResponse;


$registrationResponseJSON = '{
	"id":"MntW5QHrnIy_AGAothSeRcYMWd1Z7MgWOEaUALWlDVPl0STqOBgNAyYb-JCSxDebIJAQAoIC64ph7JsbGe7UWg",
	"rawId":"MntW5QHrnIy_AGAothSeRcYMWd1Z7MgWOEaUALWlDVPl0STqOBgNAyYb-JCSxDebIJAQAoIC64ph7JsbGe7UWg",
	"type":"public-key",
	"response":{
		"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgcUsZ2P5x-m_GHPz7RBgvyLC1HNNHtWy2Ra4zElLhCl4CIEij349Mke_G-B_ILf8UGc6U1RdJIEuwlY-bMEZGOS_6Y3g1Y4FZAsEwggK9MIIBpaADAgECAgQq52JjMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBuMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMScwJQYDVQQDDB5ZdWJpY28gVTJGIEVFIFNlcmlhbCA3MTk4MDcwNzUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqA4ZeYEPZnhH_EKolVFeEvwmvjmseOzIXKSFvVRIajNkQ05ndx2i9_kp7x-PavGLm0kaf9Wdbj_qJDMp0hp4_o2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBBtRLqb9uwuSbkwDI_pIMtzMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHJX0Dzcw-EVaYSQ1vgO-VtTByNz2eZHMmMrEdzcd4rsa9WSbQfhe5xUMHiN4y9OR7RYdv-MVSICm-k4eHlXIzHnJ3AWgopxGznHT9bBJYvR5NnlZtVweQNH2lI1wD8P_kCxQo4FxukXmeR1VHFpAe64i7BXiTWIrYiq0w1xTy8vrDbVTbrXEJxbAnqwyrjPNU7xAIoJCGyghpavDPzbwYOY_N8CMWwmIsle5iK90cAKR4nkocy3SaNUul8nYEIwvv-uBua_AvvAFbzRUd811wqYqOQtykSI_PBxBCGI3-odX3S36niLKvnFFKm6uU_nOJzaGVGQsrEwfb-RGOGpKfhoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAABNtRLqb9uwuSbkwDI_pIMtzAEAye1blAeucjL8AYCi2FJ5FxgxZ3VnsyBY4RpQAtaUNU-XRJOo4GA0DJhv4kJLEN5sgkBACggLrimHsmxsZ7tRapQECAyYgASFYIGhP2AUtUrs39wASsPlF8VYO1cJ4Qi5rLJ7AMExGFp8SIlggj7Z7WJnXU-Q6H9oQSM-U62g7xEVcqHKixwbo_KdAN7A",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI4RS1EZDRKQk1RS25kaVhvLWhYZHRqTFdQMEx5bVZaOTFNX2JCWFhydmhRIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
	}
}';

$registrationResponse = json_decode($registrationResponseJSON, true);
var_dump($registrationResponse);

$aar = new AuthenticatorAttestationResponse();
$aar->AttestationObject = $registrationResponse["response"]["attestationObject"];
$aar->ClientDataJSON = $registrationResponse["response"]["clientDataJSON"];
var_dump($aar);

try{
    $par = $aar->Parse();
    var_dump($par);
} catch (Throwable $exception) {
    var_dump($exception);
}