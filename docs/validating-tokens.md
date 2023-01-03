# Validating tokens

To validate a token you must create a new validator and assert or validate a token.

## Using `Lcobucci\JWT\Validator#assert()`

This method goes through every single constraint in the set, groups all the violations, and throws an exception with the grouped violations:

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;

require 'vendor/autoload.php';

$parser = new Parser(new JoseEncoder());

$token = $parser->parse(
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
    . 'eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
    . '2gSBz9EOsQRN9I-3iSxJoFt7NtgV6Rm0IL6a8CAwl3Q'
);

$validator = new Validator();

try {
    $validator->assert($token, new RelatedTo('1234567891')); // doesn't throw an exception
    $validator->assert($token, new RelatedTo('1234567890'));
} catch (RequiredConstraintsViolated $e) {
    // list of constraints violation exceptions:
    var_dump($e->violations());
}
```

## Using `Lcobucci\JWT\Validator#validate()`

The difference here is that we'll always get a `boolean` result and stop in the very first violation:

```php
<?php
declare(strict_types=1);

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Validator;

require 'vendor/autoload.php';

$parser = new Parser(new JoseEncoder());

$token = $parser->parse(
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
    . 'eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
    . '2gSBz9EOsQRN9I-3iSxJoFt7NtgV6Rm0IL6a8CAwl3Q'
);

$validator = new Validator();

if (! $validator->validate($token, new RelatedTo('1234567891'))) {
    echo 'Invalid token (1)!', PHP_EOL; // will print this
}

if (! $validator->validate($token, new RelatedTo('1234567890'))) {
    echo 'Invalid token (2)!', PHP_EOL; // will not print this
}
```

!!! Note
    Some systems make use of components to handle dependency injection.
    If your application follows that practice, using a [configuration object](configuration.md) might simplify the wiring of this library.


## Available constraints

This library provides the following constraints:

* `Lcobucci\JWT\Validation\Constraint\IdentifiedBy`: verifies if the claim `jti` matches the expected value
* `Lcobucci\JWT\Validation\Constraint\IssuedBy`: verifies if the claim `iss` is listed as expected values
* `Lcobucci\JWT\Validation\Constraint\PermittedFor`: verifies if the claim `aud` contains the expected value
* `Lcobucci\JWT\Validation\Constraint\RelatedTo`: verifies if the claim `sub` matches the expected value
* `Lcobucci\JWT\Validation\Constraint\SignedWith`: verifies if the token was signed with the expected signer and key
* `Lcobucci\JWT\Validation\Constraint\StrictValidAt`: verifies presence and validity of the claims `iat`, `nbf`, and `exp` (supports leeway configuration)
* `Lcobucci\JWT\Validation\Constraint\LooseValidAt`: verifies the claims `iat`, `nbf`, and `exp`, when present (supports leeway configuration)
* `Lcobucci\JWT\Validation\Constraint\HasClaimWithValue`: verifies that a **custom claim** has the expected value (not recommended when comparing cryptographic hashes)

You may also create your [own validation constraints](extending-the-library.md#validation-constraints).
