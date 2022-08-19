# Supported Algorithms

This library supports signing and verifying tokens with both symmetric and asymmetric algorithms.
Encryption is not yet supported.

Each algorithm will produce signature with different length.
If you have constraints regarding the length of the issued tokens, choose the algorithms that generate shorter output (`HS256`, `RS256`, `ES256`, and `BLAKE2B`).

## Symmetric algorithms

Symmetric algorithms perform signature creation and verification using the very same key/secret.
They're usually recommended for scenarios where these operations are handled by the very same component.

| Name      | Description        | Class                              | Key length req. |
|-----------|--------------------|------------------------------------|-----------------|
| `HS256`   | HMAC using SHA-256 | `\Lcobucci\JWT\Signer\Hmac\Sha256` | `>= 256 bits`   |
| `HS384`   | HMAC using SHA-384 | `\Lcobucci\JWT\Signer\Hmac\Sha384` | `>= 384 bits`   |
| `HS512`   | HMAC using SHA-512 | `\Lcobucci\JWT\Signer\Hmac\Sha512` | `>= 512 bits`   |
| `BLAKE2B` | Blake2b keyed Hash | `\Lcobucci\JWT\Signer\Blake2b`     | `>= 256 bits`   |

!!! Warning
    Although `BLAKE2B` is fantastic due to its performance, it's not [JWT standard] and won't necessarily be offered by other libraries.

### Deprecated items

In `v4.2.0`, we introduced key length validation and added a way for users to still use non-recommended keys.
The following implementations will be **removed** in `v5.0.0` (use them carefully):

| Name    | Description        | Class                                    | Key length req. |
|---------|--------------------|------------------------------------------|-----------------|
| `HS256` | HMAC using SHA-256 | `\Lcobucci\JWT\Signer\Hmac\UnsafeSha256` | `>= 1 bit`      |
| `HS384` | HMAC using SHA-384 | `\Lcobucci\JWT\Signer\Hmac\UnsafeSha384` | `>= 1 bit`      |
| `HS512` | HMAC using SHA-512 | `\Lcobucci\JWT\Signer\Hmac\UnsafeSha512` | `>= 1 bit`      |


## Asymmetric algorithms

Asymmetric algorithms perform signature creation with private/secret keys and verification with public keys.
They're usually recommended for scenarios where creation is handled by a component and verification by many others.

| Name    | Description                     | Class                               | Key length req. |
|---------|---------------------------------|-------------------------------------|-----------------|
| `ES256` | ECDSA using P-256 and SHA-256   | `\Lcobucci\JWT\Signer\Ecdsa\Sha256` | `== 256 bits`   |
| `ES384` | ECDSA using P-384 and SHA-384   | `\Lcobucci\JWT\Signer\Ecdsa\Sha384` | `== 384 bits`   |
| `ES512` | ECDSA using P-521 and SHA-512   | `\Lcobucci\JWT\Signer\Ecdsa\Sha512` | `== 521 bits`   |
| `RS256` | RSASSA-PKCS1-v1_5 using SHA-256 | `\Lcobucci\JWT\Signer\Rsa\Sha256`   | `>= 2048 bits`  |
| `RS384` | RSASSA-PKCS1-v1_5 using SHA-384 | `\Lcobucci\JWT\Signer\Rsa\Sha384`   | `>= 2048 bits`  |
| `RS512` | RSASSA-PKCS1-v1_5 using SHA-512 | `\Lcobucci\JWT\Signer\Rsa\Sha512`   | `>= 2048 bits`  |
| `EdDSA` | EdDSA signature algorithms      | `\Lcobucci\JWT\Signer\Eddsa`        | `>= 256 bits`   |

### Deprecated items

In `v4.2.0`, we introduced key length validation and added a way for users to still use non-recommended keys.
The following implementations will be **removed** in `v5.0.0` (use them carefully):

| Name    | Description                     | Class                                     | Key length req. |
|---------|---------------------------------|-------------------------------------------|-----------------|
| `ES256` | ECDSA using P-256 and SHA-256   | `\Lcobucci\JWT\Signer\Ecdsa\UnsafeSha256` | `>= 1 bit`      |
| `ES384` | ECDSA using P-384 and SHA-384   | `\Lcobucci\JWT\Signer\Ecdsa\UnsafeSha384` | `>= 1 bit`      |
| `ES512` | ECDSA using P-521 and SHA-512   | `\Lcobucci\JWT\Signer\Ecdsa\UnsafeSha512` | `>= 1 bit`      |
| `RS256` | RSASSA-PKCS1-v1_5 using SHA-256 | `\Lcobucci\JWT\Signer\Rsa\UnsafeSha256`   | `>= 1 bit`      |
| `RS384` | RSASSA-PKCS1-v1_5 using SHA-384 | `\Lcobucci\JWT\Signer\Rsa\UnsafeSha384`   | `>= 1 bit`      |
| `RS512` | RSASSA-PKCS1-v1_5 using SHA-512 | `\Lcobucci\JWT\Signer\Rsa\UnsafeSha512`   | `>= 1 bit`      |

[JWT standard]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
