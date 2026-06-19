# Falcon-1024 Post-Quantum Signer

This signer implements the Falcon-1024 digital signature algorithm as specified in NIST FIPS 204 (Level 5).

## Features

- 256-bit quantum resistance
- Public key: 1,793 bytes
- Private key: 2,305 bytes
- Signature: 1,280 bytes

## Usage

```php
use Lcobucci\JWT\Signer\Falcon\Falcon1024Signer;
use Lcobucci\JWT\Signer\Key\InMemory;

$signer = new Falcon1024Signer();
$key = InMemory::plainText('your-2305-byte-private-key');

$token = $builder
    ->issuedBy('https://example.com')
    ->permittedFor('https://example.org')
    ->getToken($signer, $key);

// Verify
$token->verify($signer, $publicKey);
References
NIST FIPS 204

Falcon Website

RFC 7519 (JWT)
