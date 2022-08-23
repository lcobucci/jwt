# Issuing tokens

To issue new tokens you must create a new token builder, customise it, and ask it to build the token:

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token\Builder;

require 'vendor/autoload.php';

$tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
$algorithm    = new Sha256();
$signingKey   = InMemory::plainText(random_bytes(32));

$now   = new DateTimeImmutable();
$token = $tokenBuilder
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
    ->getToken($algorithm, $signingKey);

echo $token->toString();
```

Once you've created a token, you're able to retrieve its data and convert it to its string representation:

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token\Builder;

require 'vendor/autoload.php';

$tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
$algorithm    = new Sha256();
$signingKey   = InMemory::plainText(random_bytes(32));

$token = $tokenBuilder
    ->issuedBy('http://example.com')
    ->withClaim('uid', 1)
    ->withHeader('foo', 'bar')
    ->getToken($algorithm, $signingKey);

$token->headers(); // Retrieves the token headers
$token->claims(); // Retrieves the token claims

echo $token->headers()->get('foo'), PHP_EOL; // will print "bar"
echo $token->claims()->get('iss'), PHP_EOL; // will print "http://example.com"
echo $token->claims()->get('uid'), PHP_EOL; // will print "1"

echo $token->toString(), PHP_EOL; // The string representation of the object is a JWT string

```

!!! Note
    Some systems make use of components to handle dependency injection.
    If your application follows that practice, using a [configuration object](configuration.md) might simplify the wiring of this library.
