# Quick start

Once the library has been [installed](installation.md), you are able to issue and parse JWTs.
The class `Lcobucci\JWT\JwtFacade` is the quickest way to perform these operations.

Using that facade we also aim to make sure that every token is properly signed and has the recommended claims for date control.

## Issuing tokens

The method `Lcobucci\JWT\JwtFacade#issue()` is available for quickly creating tokens.
It uses the current time to generate the date claims (default expiration is **5 minutes**).

To issue a token, call the method passing: an algorithm, a key, and a customisation function:

```php
<?php
declare(strict_types=1);

namespace MyApp;

require 'vendor/autoload.php';

use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;

use function var_dump;

$key = InMemory::base64Encoded(
    'hiG8DlOKvtih6AxlZn5XKImZ06yu8I3mkOzaJrEuW8yAv8Jnkw330uMt8AEqQ5LB'
);

$token = (new JwtFacade())->issue(
    new Sha256(),
    $key,
    static fn (
        Builder $builder,
        DateTimeImmutable $issuedAt
    ): Builder => $builder
        ->issuedBy('https://api.my-awesome-app.io')
        ->permittedFor('https://client-app.io')
        ->expiresAt($issuedAt->modify('+10 minutes'))
);

var_dump($token->claims()->all());
echo $token->toString();
```

### Creating tokens during tests

To reduce the chance of having flaky tests on your test suite, the facade supports the usage of a clock object.
That allows passing an implementation that always returns the same point in time.

You can achieve that by specifying the `clock` constructor parameter:

```php
<?php
declare(strict_types=1);

namespace MyApp;

require 'vendor/autoload.php';

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock; // If you prefer, other PSR-20 implementations may also be used
                                // (https://packagist.org/providers/psr/clock-implementation)
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\RegisteredClaims;

$clock = new FrozenClock(new DateTimeImmutable('2022-06-24 22:51:10'));
$key   = InMemory::base64Encoded(
    'hiG8DlOKvtih6AxlZn5XKImZ06yu8I3mkOzaJrEuW8yAv8Jnkw330uMt8AEqQ5LB'
);

$token = (new JwtFacade(null, $clock))->issue(
    new Sha256(),
    $key,
    static fn (
        Builder $builder,
        DateTimeImmutable $issuedAt
    ): Builder => $builder
);

echo $token->claims()->get(
    RegisteredClaims::ISSUED_AT
)->format(DateTimeImmutable::RFC3339); // 2022-06-24 22:51:10
```

## Parsing tokens

The method `Lcobucci\JWT\JwtFacade#parse()` is the one for quickly parsing tokens.
It also verifies the signature and date claims, throwing an exception in case of tokens in unexpected state.

```php
<?php
declare(strict_types=1);

namespace MyApp;

require 'vendor/autoload.php';

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock; // If you prefer, other PSR-20 implementations may also be used
                                // (https://packagist.org/providers/psr/clock-implementation)
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint;

use function var_dump;

$jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTg2OTYwNTIsIm5iZiI6MT'
    . 'Y1ODY5NjA1MiwiZXhwIjoxNjU4Njk2NjUyLCJpc3MiOiJodHRwczovL2FwaS5teS1hd2Vzb'
    . '21lLWFwcC5pbyIsImF1ZCI6Imh0dHBzOi8vY2xpZW50LWFwcC5pbyJ9.yzxpjyq8lXqMgaN'
    . 'rMEOLUr7R0brvhwXx0gp56uWEIfc';

$key = InMemory::base64Encoded(
    'hiG8DlOKvtih6AxlZn5XKImZ06yu8I3mkOzaJrEuW8yAv8Jnkw330uMt8AEqQ5LB'
);

$token = (new JwtFacade())->parse(
    $jwt,
    new Constraint\SignedWith(new Sha256(), $key),
    new Constraint\StrictValidAt(
        new FrozenClock(new DateTimeImmutable('2022-07-24 20:55:10+00:00'))
    )
);

var_dump($token->claims()->all());
```

!!! Warning
    The example above uses `FrozenClock` as clock implementation to make sure that code will always work.
    Use `SystemClock` on the production code of your application, allowing the parser to correctly verify the date claims.
