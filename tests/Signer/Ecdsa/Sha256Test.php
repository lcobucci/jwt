<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key;

use const OPENSSL_ALGO_SHA256;

/**
 * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
 * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
 * @covers \Lcobucci\JWT\Signer\Ecdsa
 * @covers \Lcobucci\JWT\Signer\OpenSSL
 * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 */
final class Sha256Test extends EcdsaTestCase
{
    protected function algorithm(): Ecdsa
    {
        return new Sha256($this->pointsManipulator);
    }

    protected function algorithmId(): string
    {
        return 'ES256';
    }

    protected function signatureAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    protected function pointLength(): int
    {
        return 64;
    }

    protected function keyLength(): int
    {
        return 256;
    }

    protected function verificationKey(): Key
    {
        return self::$ecdsaKeys['public1'];
    }

    protected function signingKey(): Key
    {
        return self::$ecdsaKeys['private'];
    }

    /** {@inheritdoc} */
    public static function incompatibleKeys(): iterable
    {
        yield '384 bits' => ['private_ec384', 384];
        yield '521 bits' => ['private_ec512', 521];
    }
}
