# Parsing tokens

!!! Note
    The examples here fetch the configuration object from a hypothetical dependency injection container.
    You can create it in the same script or require it from a different file. It basically depends on how your system is bootstrapped.

To parse a token you must create a new parser (easier when using the [configuration object](configuration.md)) and ask it to parse a string:

```php
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;

$config = $container->get(Configuration::class);
assert($config instanceof Configuration);

$token = $config->parser()->parse(
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
    . 'eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
    . '2gSBz9EOsQRN9I-3iSxJoFt7NtgV6Rm0IL6a8CAwl3Q'
);

assert($token instanceof Plain);

$token->headers(); // Retrieves the token headers
$token->claims(); // Retrieves the token claims
```

!!! Important
    In case of parsing errors the Parser will throw an exception of type `InvalidArgumentException`.
