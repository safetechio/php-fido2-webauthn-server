# FIDO2_SERVER_Libraries

## WebAuthn

### WebAuthn Initialise

```php
<?php
// Initialise

use SAFETECHio\FIDO2\WebAuthn;

$WebAConfig = new WebAuthn\WebAuthnConfig(
    "Example Name",
    "example.com",
    "https://login.example.com",          // Optional
    "https://example.com/images/logo.png" // Optional
); 
$WebA = new WebAuthn\WebAuthnServer($WebAConfig);
```

### WebAuthn Register User

#### WebAuthn Begin Registration

```php
<?php
// Begin Registration

use SAFETECHio\FIDO2\WebAuthn;

// create or find the registering user from your data store
$user = User::FindOrCreate();  

/** @var $WebA WebAuthn\WebAuthnServer */
list($options, $sessionData) = $WebA->beginRegistration($user);

// sessionData should be saved in the registration session
session_start();
$_SESSION['registration_session'] = $sessionData;

echo json_encode($options);
// respond with the options
// options->publicKey contains the registration options
```

#### WebAuthn Complete Registration

```php
<?php
// Complete Registration

use SAFETECHio\FIDO2\WebAuthn;

// find the registering user from your data store
$user = User::Find();  

// Get the session data stored in the beginRegistration step
session_start();
$sessionData = $_SESSION['registration_session'];

// Call the WebAuthn->completeRegistration() func
/** @var $WebA WebAuthn\WebAuthnServer */
$credential = $WebA->completeRegistration($user, $sessionData);

// If creation was successful, store the credential object
WebAuthn\Credential::Create($credential);

// Destroy the registration session
unset($_SESSION['registration_session']);

// Respond with a success message
echo json_encode("Registration Success");
```

### WebAuthn Authenticate User

#### WebAuthn Begin Authentication
```php
<?php
// Begin Authentication

use SAFETECHio\FIDO2\WebAuthn;

// find the registering user from your data store
$user = User::Find();

/** @var $WebA WebAuthn\WebAuthnServer */
list($options, $sessionData) = $WebA->beginAuthentication($user);

// sessionData should be saved in the authentication session
session_start();
$_SESSION['authentication_session'] = $sessionData;

echo json_encode($options);
// respond with the options
// options->publicKey contains the registration options
```

#### WebAuthn Complete Authentication

```php
<?php
// Complete Authentication

use SAFETECHio\FIDO2\WebAuthn;

// find the registering user from your data store
$user = User::Find();

// Get the authentication session data stored in the beginAuthentication step
session_start();
$sessionData = $_SESSION['authentication_session'];

/** @var $WebA WebAuthn\WebAuthnServer */
$credential = $WebA->completeAuthentication($user, $sessionData);

// Destroy the registration session
unset($_SESSION['authentication_session']);

// Respond with a success message
echo json_encode("Registration Success");
```