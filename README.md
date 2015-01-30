# JWT
[![Gitter](https://img.shields.io/badge/GITTER-JOIN%20CHAT%20%E2%86%92-brightgreen.svg?style=flat-square)](https://gitter.im/lcobucci/jwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![Total Downloads](https://img.shields.io/packagist/dt/lcobucci/jwt.svg?style=flat-square)](https://packagist.org/packages/lcobucci/jwt) [![Latest Stable Version](https://img.shields.io/packagist/v/lcobucci/jwt.svg?style=flat-square)](https://packagist.org/packages/lcobucci/jwt)

![Branch master](https://img.shields.io/badge/branch-master-brightgreen.svg?style=flat-square)
[![Build Status](https://img.shields.io/travis/lcobucci/jwt/master.svg?style=flat-square)](http://travis-ci.org/#!/lcobucci/jwt)
[![Scrutinizer Code Quality](https://img.shields.io/scrutinizer/g/lcobucci/jwt/master.svg?style=flat-square)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=master)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/lcobucci/jwt/master.svg?style=flat-square)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=master)

![Branch develop](https://img.shields.io/badge/branch-develop-brightgreen.svg?style=flat-square)
[![Build Status](https://img.shields.io/travis/lcobucci/jwt/develop.svg?style=flat-square)](http://travis-ci.org/#!/lcobucci/jwt)
[![Scrutinizer Code Quality](https://img.shields.io/scrutinizer/g/lcobucci/jwt/develop.svg?style=flat-square)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=develop)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/lcobucci/jwt/develop.svg?style=flat-square)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=develop)


A simple library to work with JSON Web Token and JSON Web Signature (requires PHP 5.5+).
The implementation is based on the [current draft](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31).

## Instalation

Just add to your composer.json: ```"lcobucci/jwt": "*"```

### Dependencies

- PHP 5.5+

## Basic usage

### Creating

Just use the builder to create a new JWT/JWS tokens:

```php
<?php
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;

$token = (new Builder())->setIssuer('http://example.com') // Configures the issuer (iss claim)
                        ->setAudience('http://example.org') // Configures the audience (aud claim)
                        ->setId('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
                        ->set('uid', 1) // Configures a new claim, called "uid"
                        ->sign(new Sha256(), 'my key') // Signs the token with HS256 using "my key" as key
                        ->getToken(); // Retrieves the generated token

echo $token; // The string representation of the object is a JWT string (pretty easy, right?)
```
### Parsing from strings

Use the parser to create a new token from a JWT string:

```php
<?php
use Lcobucci\JWT\Parser;

$token = (new Parser())->parse('...'); // Parses from a string
$token->getHeader(); // Retrieves the token header
$token->getClaims(); // Retrieves the token claims
$token->verify('my key'); // Verifies if the signature was created with given key (if token is signed)
```
