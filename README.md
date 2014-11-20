# JWT

master
[![Build Status](https://secure.travis-ci.org/lcobucci/jwt.png?branch=master)](http://travis-ci.org/#!/lcobucci/jwt)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/lcobucci/jwt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/lcobucci/jwt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=master)

develop
[![Build Status](https://secure.travis-ci.org/lcobucci/jwt.png?branch=develop)](http://travis-ci.org/#!/lcobucci/jwt)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/lcobucci/jwt/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=develop)
[![Code Coverage](https://scrutinizer-ci.com/g/lcobucci/jwt/badges/coverage.png?b=develop)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=develop)

[![Total Downloads](https://poser.pugx.org/lcobucci/jwt/downloads.png)](https://packagist.org/packages/lcobucci/jwt)
[![Latest Stable Version](https://poser.pugx.org/lcobucci/jwt/v/stable.png)](https://packagist.org/packages/lcobucci/jwt)

A simple library to work with JSON Web Token and JSON Web Signature (requires PHP 5.5+)

## Instalation

Just add to your composer.json: ```"lcobucci/jwt": "*"```

## Basic usage

### Creating

Just use the builder to create a new JWT/JWS tokens:

```php
<?php
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Sha256;

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
