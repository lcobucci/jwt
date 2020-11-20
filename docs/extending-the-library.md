# Extending the library

!!! Note
    The examples here fetch the configuration object from a hypothetical dependency injection container.
    You can create it in the same script or require it from a different file. It basically depends on how your system is bootstrapped.

We've designed a few extension points in this library.
These should enable people to easily customise our core components if they want to.

## Builder

The token builder defines a fluent interface for plain token creation.

To create your own builder of it you must implement the `Lcobucci\JWT\Builder` interface:

```php
use Lcobucci\JWT\Builder;

final class MyCustomTokenBuilder implements Builder
{
    // implement all methods
}
```

Then, register a custom factory in the [configuration object]:

```php
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;

$config = $container->get(Configuration::class);
assert($config instanceof Configuration);

$config->setBuilderFactory(
    static function (ClaimsFormatter $formatter): Builder {
        return new MyCustomTokenBuilder($formatter);
    }
);
```

## Claims formatter

By default, we provide formatters that:

- unify the audience claim, making sure we use strings when there's only one item in that claim
- format date based claims using microseconds (float)

You may customise and even create your own formatters:

```php
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\RegisteredClaims;

final class UnixTimestampDates implements ClaimsFormatter
{
    /** @inheritdoc  */
    public function formatClaims(array $claims): array
    {
        foreach (RegisteredClaims::DATE_CLAIMS as $claim) {
            if (! array_key_exists($claim, $claims)) {
                continue;
            }

            assert($claims[$claim] instanceof DateTimeImmutable);
            $claims[$claim] = $claims[$claim]->getTimestamp();
        }

        return $claims;
    }
}

$config = $container->get(Configuration::class);
assert($config instanceof Configuration);

$config->builder(new UnixTimestampDates());
```

The class `Lcobucci\JWT\Encoding\ChainedFormatter` allows for users to combine multiple formatters. 

## Parser

The token parser defines how a JWT string should be converted into token objects.

To create your own parser of it you must implement the `Lcobucci\JWT\Parser` interface:

```php
use Lcobucci\JWT\Parser;

final class MyCustomTokenParser implements Parser
{
    // implement all methods
}
```

Then register an instance in the [configuration object]:

```php
use Lcobucci\JWT\Configuration;

$config = $container->get(Configuration::class);
assert($config instanceof Configuration);

$config->setParser(new MyCustomTokenParser());
```

## Signer

The signer defines how to create and verify signatures.

To create your own signer of it you must implement the `Lcobucci\JWT\Signer` interface:

```php
use Lcobucci\JWT\Signer;

final class SignerForAVeryCustomizedAlgorithm implements Signer
{
    // implement all methods
}
```

Then pass an instance of it while creating an instance of the [configuration object], [issuing a token](issuing-tokens.md), or [validating a token].

## Key

The key object is passed down to signers and provide the necessary information to create and verify signatures.

To create your own signer of it you must implement the `Lcobucci\JWT\Signer\Key` interface:

```php
use Lcobucci\JWT\Signer\Key;

final class KeyWithSomeMagicalProperties implements Key
{
    // implement all methods
}
```

## Validator

The token validator defines how to apply validation constraint to either validate or assert tokens.

To create your own validator of it you must implement the `Lcobucci\JWT\Validator` interface:

```php
use Lcobucci\JWT\Validator;

final class MyCustomTokenValidator implements Validator
{
    // implement all methods
}
```

Then register an instance in the [configuration object]:

```php
use Lcobucci\JWT\Configuration;

$config = $container->get(Configuration::class);
assert($config instanceof Configuration);

$config->setValidator(new MyCustomTokenValidator());
```

## Validation constraints

A validation constraint define how one or more claims/headers should be validated.
Custom validation constraints are handy to provide advanced rules for the registered claims or to validate private claims.

To create your own implementation of constraint you must implement the `Lcobucci\JWT\Validation\Constraint` interface:

```php
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class SubjectMustBeAValidUser implements Constraint
{
    public function assert(Token $token): void
    {
        if (! $token instanceof Token\Plain) {
            throw new ConstraintViolation('You should pass a plain token');
        }

        if (! $this->existsInDatabase($token->claims()->get('sub'))) {
            throw new ConstraintViolation('Token related to an unknown user');
        }
    }

    private function existsInDatabase(string $userId): bool
    {
        // ...
    }
}
```

Then use it while [validating a token].

[configuration object]: configuration.md
[validating a token]: validating-tokens.md
