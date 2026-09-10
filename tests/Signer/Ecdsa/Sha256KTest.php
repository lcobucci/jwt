<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256K;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\OpenSSL;
use PHPUnit\Framework\Attributes as PHPUnit;

use function str_repeat;

use const OPENSSL_ALGO_SHA256;

#[PHPUnit\CoversClass(Ecdsa::class)]
#[PHPUnit\CoversClass(Ecdsa\MultibyteStringConverter::class)]
#[PHPUnit\CoversClass(Sha256K::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(Key\InMemory::class)]
final class Sha256KTest extends EcdsaTestCase
{
    protected function algorithm(): Ecdsa
    {
        return new Sha256K($this->pointsManipulator);
    }

    protected function algorithmId(): string
    {
        return 'ES256K';
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
        return self::$ecdsaKeys['public_secp256k1'];
    }

    protected function signingKey(): Key
    {
        return self::$ecdsaKeys['private_secp256k1'];
    }

    /** {@inheritDoc} */
    public static function incompatibleKeys(): iterable
    {
        yield '384 bits' => ['private_ec384', 384];
        yield '521 bits' => ['private_ec512', 521];
    }

    #[PHPUnit\Test]
    public function expectedCurveMustBeCorrect(): void
    {
        self::assertSame('secp256k1', $this->algorithm()->expectedCurve());
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyCurveIsNotSecp256k1(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains(
            'The curve of the provided key is not "secp256k1", "prime256v1" provided',
        );

        $this->algorithm()->sign('testing', self::$ecdsaKeys['private']);
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyCurveIsNotSecp256k1(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains(
            'The curve of the provided key is not "secp256k1", "prime256v1" provided',
        );

        $this->algorithm()->verify(str_repeat('a', 64), 'testing', self::$ecdsaKeys['public1']);
    }
}
