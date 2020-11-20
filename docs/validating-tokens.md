# Validating tokens

!!! Note
    The examples here fetch the configuration object from a hypothetical dependency injection container.
    You can create it in the same script or require it from a different file. It basically depends on how your system is bootstrapped.

To validate a token you must create a new validator (easier when using the [configuration object](configuration.md)) and assert or validate a token.

## Using `Lcobucci\JWT\Validator#assert()`

!!! Warning
    You **MUST** provide at least one constraint, otherwise `\Lcobucci\JWT\Validation\NoConstraintsGiven` exception will be thrown.

This method goes through every single constraint in the set, groups all the violations, and throws an exception with the grouped violations:

```php
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

$token = $container->get(Configuration::class);
assert($config instanceof Configuration);

$token = $config->parser()->parse('...');
assert($token instanceof Plain);

$constraints = $config->validationConstraints();

try {
    $config->validator()->assert($token, ...$constraints);
} catch (RequiredConstraintsViolated $e) {
    // list of constraints violation exceptions:
    var_dump($e->violations());
}
```

## Using `Lcobucci\JWT\Validator#validate()`

!!! Warning
    You **MUST** provide at least one constraint, otherwise `\Lcobucci\JWT\Validation\NoConstraintsGiven` exception will be thrown.

The difference here is that we'll always a get a `boolean` result and stop in the very first violation:

```php
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;

$token = $container->get(Configuration::class);
assert($config instanceof Configuration);

$token = $config->parser()->parse('...');
assert($token instanceof Plain);

$constraints = $config->validationConstraints();

if (! $config->validator()->validate($token, ...$constraints)) {
   throw new RuntimeException('No way!');
}
```

## Available constraints

This library provides the following constraints:

* `Lcobucci\JWT\Validation\Constraint\IdentifiedBy`: verifies if the claim `jti` matches the expected value
* `Lcobucci\JWT\Validation\Constraint\IssuedBy`: verifies if the claim `iss` is listed as expected values
* `Lcobucci\JWT\Validation\Constraint\PermittedFor`: verifies if the claim `aud` contains the expected value
* `Lcobucci\JWT\Validation\Constraint\RelatedTo`: verifies if the claim `sub` matches the expected value
* `Lcobucci\JWT\Validation\Constraint\SignedWith`: verifies if the token was signed with the expected signer and key
* `Lcobucci\JWT\Validation\Constraint\ValidAt`: verifies the claims `iat`, `nbf`, and `exp` (supports leeway configuration)

You may also create your [own validation constraints](extending-the-library.md#validation-constraints).
