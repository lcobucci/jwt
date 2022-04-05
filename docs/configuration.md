# Configuration

In order to simplify the setup of the library, we provide the class `Lcobucci\JWT\Configuration`.

It's meant for:

* Configuring the default algorithm (signer) and key(s) to be used
* Configuring the default set of validation constraints
* Providing custom implementation for the [extension points](extending-the-library.md)
* Retrieving components (encoder, decoder, parser, validator, and builder)

## Usage

In order to use it, you must:

1. Initialise the configuration object
1. Customise the configuration object
1. Retrieve components

### Configuration initialisation

The `Lcobucci\JWT\Signer\Key\InMemory` object is used for symmetric/asymmetric signature.

To initialise it, you can pass the key content as a plain text:

```php
use Lcobucci\JWT\Signer\Key\InMemory;

$key = InMemory::plainText('my-key-as-plaintext');
```

Provide a base64 encoded string:

```php
use Lcobucci\JWT\Signer\Key\InMemory;

$key = InMemory::base64Encoded('YSB2ZXJ5IGxvbmcgYSB2ZXJ5IHVsdHJhIHNlY3VyZSBrZXkgZm9yIG15IGFtYXppbmcgdG9rZW5z');
```

Or provide a file path:

```php
use Lcobucci\JWT\Signer\Key\InMemory;

$key = InMemory::file(__DIR__ . '/path-to-my-key-stored-in-a-file.pem'); // this reads the file and keeps its contents in memory
```

#### For symmetric algorithms

Symmetric algorithms use the same key for both signature creation and verification.
This means that it's really important that your key **remains secret**.

!!! Tip
    It is recommended that you use a key with lots of entropy, preferably generated using a cryptographically secure pseudo-random number generator (CSPRNG).
    You can use the [CryptoKey](https://github.com/AndrewCarterUK/CryptoKey) tool to do this for you.

```php
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;

$configuration = Configuration::forSymmetricSigner(
    // You may use any HMAC variations (256, 384, and 512)
    new Sha256(),
    // replace the value below with a key of your own!
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
    // You may also override the JOSE encoder/decoder if needed by providing extra arguments here
);
```

Currently supported symmetric algorithms:

| Name      | Description        | Class                               | Key length req. | Notes                                                                                                      |
|-----------|--------------------|-------------------------------------|-----------------|------------------------------------------------------------------------------------------------------------|
| `HS256`   | HMAC using SHA-256 | `\Lcobucci\JWT\Signer\Hmac\Sha256`  | 256 bits        |                                                                                                            |
| `HS384`   | HMAC using SHA-384 | `\Lcobucci\JWT\Signer\Hmac\Sha384`  | 384 bits        |                                                                                                            |
| `HS512`   | HMAC using SHA-512 | `\Lcobucci\JWT\Signer\Hmac\Sha512`  | 512 bits        |                                                                                                            |
| `BLAKE2B` | Blake2b keyed Hash | `\Lcobucci\JWT\Signer\Hmac\Blake2b` | 256 bits        | Not a [JWT standard](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms) |

Deprecated symmetric algorithms in `v4`:

| Name      | Description        | Class                                    | Key length req. |
| --------- | ------------------ | ---------------------------------------- |-----------------|
| `HS256`   | HMAC using SHA-256 | `\Lcobucci\JWT\Signer\Hmac\UnsafeSha256` | 1 bit           |
| `HS384`   | HMAC using SHA-384 | `\Lcobucci\JWT\Signer\Hmac\UnsafeSha384` | 1 bit           |
| `HS512`   | HMAC using SHA-512 | `\Lcobucci\JWT\Signer\Hmac\UnsafeSha512` | 1 bit           |

#### For asymmetric algorithms

Asymmetric algorithms use a **private key** for signature creation and a **public key** for verification.
This means that it's fine to distribute your **public key**. However, the **private key** should **remain secret**.

```php
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;

$configuration = Configuration::forAsymmetricSigner(
    // You may use RSA or ECDSA and all their variations (256, 384, and 512) and EdDSA over Curve25519
    new Signer\Rsa\Sha256(),
    InMemory::file(__DIR__ . '/my-private-key.pem'),
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
    // You may also override the JOSE encoder/decoder if needed by providing extra arguments here
);
```

!!! Important
    The implementation of ECDSA algorithms have a constructor dependency.
    Use the `create()` named constructor to avoid having to handle it (e.g.: `Lcobucci\JWT\Signer\Ecdsa\Sha256::create()`).

Currently supported asymmetric algorithms:

| Name    | Description                     | Class                               | Key length req. |
| ------- | ------------------------------- | ----------------------------------- |-----------------|
| `ES256` | ECDSA using P-256 and SHA-256   | `\Lcobucci\JWT\Signer\Ecdsa\Sha256` | 224 bits        |
| `ES384` | ECDSA using P-384 and SHA-384   | `\Lcobucci\JWT\Signer\Ecdsa\Sha384` | 224 bits        |
| `ES512` | ECDSA using P-521 and SHA-512   | `\Lcobucci\JWT\Signer\Ecdsa\Sha512` | 224 bits        |
| `RS256` | RSASSA-PKCS1-v1_5 using SHA-256 | `\Lcobucci\JWT\Signer\Rsa\Sha256`   | 2048 bits       |
| `RS384` | RSASSA-PKCS1-v1_5 using SHA-384 | `\Lcobucci\JWT\Signer\Rsa\Sha384`   | 2048 bits       |
| `RS512` | RSASSA-PKCS1-v1_5 using SHA-512 | `\Lcobucci\JWT\Signer\Rsa\Sha512`   | 2048 bits       |
| `EdDSA` | EdDSA signature algorithms      | `\Lcobucci\JWT\Signer\Eddsa`        | 256 bits        |

Deprecated asymmetric algorithms in `v4`:

| Name    | Description                     | Class                                     | Key length req. |
| ------- | ------------------------------- |-------------------------------------------|-----------------|
| `ES256` | ECDSA using P-256 and SHA-256   | `\Lcobucci\JWT\Signer\Ecdsa\UnsafeSha256` | 1 bit           |
| `ES384` | ECDSA using P-384 and SHA-384   | `\Lcobucci\JWT\Signer\Ecdsa\UnsafeSha384` | 1 bit           |
| `ES512` | ECDSA using P-521 and SHA-512   | `\Lcobucci\JWT\Signer\Ecdsa\UnsafeSha512` | 1 bit           |
| `RS256` | RSASSA-PKCS1-v1_5 using SHA-256 | `\Lcobucci\JWT\Signer\Rsa\UnsafeSha256`   | 1 bit           |
| `RS384` | RSASSA-PKCS1-v1_5 using SHA-384 | `\Lcobucci\JWT\Signer\Rsa\UnsafeSha384`   | 1 bit           |
| `RS512` | RSASSA-PKCS1-v1_5 using SHA-512 | `\Lcobucci\JWT\Signer\Rsa\UnsafeSha512`   | 1 bit           |

#### For no algorithm

!!! Warning
    This configuration type is **NOT** recommended for production environments.
    It's only provided to allow people to have a simpler and faster setup for tests, avoiding any kind of signature creation/verification.

```php
use Lcobucci\JWT\Configuration;

$configuration = Configuration::forUnsecuredSigner(
    // You may also override the JOSE encoder/decoder if needed by providing extra arguments here
);
```

### Customisation

By using the setters of the `Lcobucci\JWT\Configuration` you may customise the setup of this library.

!!! Important
    If you want to use a customised configuration, please make sure you call the setters before of invoking any getter.
    Otherwise, the default implementations will be used.

These are the available setters:

* `Lcobucci\JWT\Configuration#setBuilderFactory()`: configures how the token builder should be created
* `Lcobucci\JWT\Configuration#setParser()`: configures a custom token parser
* `Lcobucci\JWT\Configuration#setValidator()`: configures a custom validator
* `Lcobucci\JWT\Configuration#setValidationConstraints()`: configures the default set of validation constraints

### Retrieve components

Once you've made all the necessary configuration you can pass the configuration object around your code and use the getters to retrieve the components:

These are the available getters:

* `Lcobucci\JWT\Configuration#builder()`: retrieves the token builder (always creating a new instance)
* `Lcobucci\JWT\Configuration#parser()`: retrieves the token parser
* `Lcobucci\JWT\Configuration#signer()`: retrieves the signer
* `Lcobucci\JWT\Configuration#signingKey()`: retrieves the key for signature creation
* `Lcobucci\JWT\Configuration#verificationKey()`: retrieves the key for signature verification
* `Lcobucci\JWT\Configuration#validator()`: retrieves the token validator
* `Lcobucci\JWT\Configuration#validationConstraints()`: retrieves the default set of validation constraints
