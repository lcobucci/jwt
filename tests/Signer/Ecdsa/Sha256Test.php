<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\OpenSSL;
use PHPUnit\Framework\Attributes as PHPUnit;

use const OPENSSL_ALGO_SHA256;

#[PHPUnit\CoversClass(Ecdsa::class)]
#[PHPUnit\CoversClass(Ecdsa\MultibyteStringConverter::class)]
#[PHPUnit\CoversClass(Ecdsa\Sha256::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(Key\InMemory::class)]
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

    /** {@inheritDoc} */
    public static function incompatibleKeys(): iterable
    {
        yield '384 bits' => ['private_ec384', 384];
        yield '521 bits' => ['private_ec512', 521];
    }
}
