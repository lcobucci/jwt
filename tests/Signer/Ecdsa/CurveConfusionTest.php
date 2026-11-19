<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Tests\Keys;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function str_repeat;

/**
 * secp256k1 (used by ES256K) and P-256 (used by ES256) both produce 256-bit keys, so a key-length
 * check alone is not enough to tell them apart. These tests make sure each ECDSA algorithm also
 * validates the curve of the key it receives, per RFC 8812 section 3.2:
 * https://www.rfc-editor.org/rfc/rfc8812#section-3.2
 */
#[PHPUnit\CoversClass(Ecdsa::class)]
#[PHPUnit\CoversClass(Ecdsa\MultibyteStringConverter::class)]
#[PHPUnit\CoversClass(Sha256::class)]
#[PHPUnit\CoversClass(Sha384::class)]
#[PHPUnit\CoversClass(Sha512::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(Key\InMemory::class)]
final class CurveConfusionTest extends TestCase
{
    use Keys;

    #[PHPUnit\Test]
    public function sha256ExpectedCurveMustBeCorrect(): void
    {
        self::assertSame('prime256v1', (new Sha256())->expectedCurve());
    }

    #[PHPUnit\Test]
    public function sha384ExpectedCurveMustBeCorrect(): void
    {
        self::assertSame('secp384r1', (new Sha384())->expectedCurve());
    }

    #[PHPUnit\Test]
    public function sha512ExpectedCurveMustBeCorrect(): void
    {
        self::assertSame('secp521r1', (new Sha512())->expectedCurve());
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenEs256IsGivenASecp256k1KeyOfMatchingLength(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains(
            'The curve of the provided key is not "prime256v1", "secp256k1" provided',
        );

        (new Sha256())->sign('testing', self::$ecdsaKeys['private_secp256k1']);
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenEs256IsGivenASecp256k1KeyOfMatchingLength(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains(
            'The curve of the provided key is not "prime256v1", "secp256k1" provided',
        );

        (new Sha256())->verify(str_repeat('a', 64), 'testing', self::$ecdsaKeys['public_secp256k1']);
    }
}
