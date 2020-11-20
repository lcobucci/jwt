# Issuing tokens

!!! Note
    The examples here fetch the configuration object from a hypothetical dependency injection container.
    You can create it in the same script or require it from a different file. It basically depends on how your system is bootstrapped.

To issue new tokens you must create a new token a builder (easier when using the [configuration object](configuration.md)), customise it, and ask it to build the token:

```php
use Lcobucci\JWT\Configuration;

$config = $container->get(Configuration::class);
assert($config instanceof Configuration);

$now   = new DateTimeImmutable();
$token = $config->builder()
                // Configures the issuer (iss claim)
                ->issuedBy('http://example.com')
                // Configures the audience (aud claim)
                ->permittedFor('http://example.org')
                // Configures the id (jti claim)
                ->identifiedBy('4f1g23a12aa')
                // Configures the time that the token was issue (iat claim)
                ->issuedAt($now)
                // Configures the time that the token can be used (nbf claim)
                ->canOnlyBeUsedAfter($now->modify('+1 minute'))
                // Configures the expiration time of the token (exp claim)
                ->expiresAt($now->modify('+1 hour'))
                // Configures a new claim, called "uid"
                ->withClaim('uid', 1)
                // Configures a new header, called "foo"
                ->withHeader('foo', 'bar')
                // Builds a new token
                ->getToken($config->signer(), $config->signingKey());
```

Once you've created a token, you're able to retrieve its data and convert it to its string representation:

```php
use Lcobucci\JWT\Configuration;

$config = $container->get(Configuration::class);
assert($config instanceof Configuration);

$token = $config->builder()
                ->issuedBy('http://example.com')
                ->withClaim('uid', 1)
                ->withHeader('foo', 'bar')
                ->getToken($config->signer(), $config->signingKey());

$token->headers(); // Retrieves the token headers
$token->claims(); // Retrieves the token claims

echo $token->headers()->get('foo'); // will print "bar"
echo $token->claims()->get('iss'); // will print "http://example.com"
echo $token->claims()->get('uid'); // will print "1"

echo $token->toString(); // The string representation of the object is a JWT string
```
