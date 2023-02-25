# Configuration

In order to simplify the setup of the library, we provide the class `Lcobucci\JWT\Configuration`.

It's meant for:

* Configuring the default algorithm (signer) and key(s) to be used
* Configuring the default set of validation constraints
* Providing custom implementation for the [extension points](extending-the-library.md)
* Retrieving components (encoder, decoder, parser, validator, and builder)

## Initialisation

The `Lcobucci\JWT\Signer\Key\InMemory` object is used for symmetric/asymmetric signature.

To initialise it, you can pass the key content as a plain text:

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Signer\Key\InMemory;

require 'vendor/autoload.php';

$key = InMemory::plainText('my-key-as-plaintext');
```

Provide a base64 encoded string:

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Signer\Key\InMemory;

require 'vendor/autoload.php';

$key = InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=');
```

Or provide a file path:

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Signer\Key\InMemory;

require 'vendor/autoload.php';

// this reads the file and keeps its contents in memory
$key = InMemory::file(__DIR__ . '/path-to-my-key-stored-in-a-file.pem');
```

### For symmetric algorithms

[Symmetric algorithms](supported-algorithms.md#symmetric-algorithms) use the same key for both signature creation and verification.
This means that it's really important that your key **remains secret**.

!!! Tip
    It is recommended that you use a key with lots of entropy, preferably generated using a cryptographically secure pseudo-random number generator (CSPRNG).
    You can use the [CryptoKey](https://github.com/AndrewCarterUK/CryptoKey) tool to do this for you.

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;

require 'vendor/autoload.php';

$configuration = Configuration::forSymmetricSigner(
    new Signer\Hmac\Sha256(),
    // replace the value below with a key of your own!
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
    // You may also override the JOSE encoder/decoder if needed
    // by providing extra arguments here
);
```

### For asymmetric algorithms

[Asymmetric algorithms](supported-algorithms.md#asymmetric-algorithms) use a **private key** for signature creation and a **public key** for verification.
This means that it's fine to distribute your **public key**. However, the **private key** should **remain secret**.

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;

require 'vendor/autoload.php';

$configuration = Configuration::forAsymmetricSigner(
    new Signer\Rsa\Sha256(),
    InMemory::file(__DIR__ . '/my-private-key.pem'),
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
    // You may also override the JOSE encoder/decoder if needed
    // by providing extra arguments here
);
```

## Customisation

By using the setters of the `Lcobucci\JWT\Configuration` you may customise the setup of this library.

!!! Important
    If you want to use a customised configuration, please make sure you call the setters before of invoking any getter.
    Otherwise, the default implementations will be used.

### Builder factory

It configures how the token builder should be created.
It's useful when you want to provide a [custom Builder](extending-the-library.md#builder).

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;

require 'vendor/autoload.php';

$configuration = Configuration::forSymmetricSigner(
    new Signer\Hmac\Sha256(),
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
);

$configuration->setBuilderFactory(
    static function (ClaimsFormatter $formatter): Builder {
        // This assumes `MyCustomBuilder` is an existing class 
        return new MyCustomBuilder(new JoseEncoder(), $formatter);
    }
);
```

### Parser

It configures how the token parser should be created.
It's useful when you want to provide a [custom Parser](extending-the-library.md#parser).

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;

require 'vendor/autoload.php';

$configuration = Configuration::forSymmetricSigner(
    new Signer\Hmac\Sha256(),
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
);

// This assumes `MyParser` is an existing class 
$configuration->setParser(new MyParser());
```

### Validator

It configures how the token validator should be created.
It's useful when you want to provide a [custom Validator](extending-the-library.md#validator).

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;

require 'vendor/autoload.php';

$configuration = Configuration::forSymmetricSigner(
    new Signer\Hmac\Sha256(),
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
);

// This assumes `MyValidator` is an existing class
$configuration->setValidator(new MyValidator());
```

### Validation constraints

It configures which are the base constraints to be used during validation.

```php
<?php
declare(strict_types=1);

use Lcobucci\Clock\SystemClock; // If you prefer, other PSR-20 implementations may also be used
                                // (https://packagist.org/providers/psr/clock-implementation)
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;

require 'vendor/autoload.php';

$configuration = Configuration::forSymmetricSigner(
    new Signer\Hmac\Sha256(),
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
);

$configuration->setValidationConstraints(
    new SignedWith($configuration->signer(), $configuration->signingKey()),
    new StrictValidAt(SystemClock::fromUTC()),
    new IssuedBy('https://api.my-awesome-company.com')
);
```

## Retrieve components

Once you've made all the necessary configuration you can pass the configuration object around your code and use the getters to retrieve the components:

These are the available getters:

* `Lcobucci\JWT\Configuration#builder()`: retrieves the token builder (always creating a new instance)
* `Lcobucci\JWT\Configuration#parser()`: retrieves the token parser
* `Lcobucci\JWT\Configuration#signer()`: retrieves the signer
* `Lcobucci\JWT\Configuration#signingKey()`: retrieves the key for signature creation
* `Lcobucci\JWT\Configuration#verificationKey()`: retrieves the key for signature verification
* `Lcobucci\JWT\Configuration#validator()`: retrieves the token validator
* `Lcobucci\JWT\Configuration#validationConstraints()`: retrieves the default set of validation constraints
