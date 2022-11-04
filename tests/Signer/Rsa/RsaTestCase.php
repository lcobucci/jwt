<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Rsa;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Tests\Keys;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

use function assert;
use function openssl_error_string;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

use const PHP_EOL;

abstract class RsaTestCase extends TestCase
{
    use Keys;

    abstract protected function algorithm(): Rsa;

    abstract protected function algorithmId(): string;

    abstract protected function signatureAlgorithm(): int;

    /** @after */
    final public function clearOpenSSLErrors(): void
    {
        // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        while (openssl_error_string()) {
        }
    }

    /** @test */
    final public function algorithmIdMustBeCorrect(): void
    {
        self::assertSame($this->algorithmId(), $this->algorithm()->algorithmId());
    }

    /** @test */
    final public function signatureAlgorithmMustBeCorrect(): void
    {
        self::assertSame($this->signatureAlgorithm(), $this->algorithm()->algorithm());
    }

    /** @test */
    public function signShouldReturnAValidOpensslSignature(): void
    {
        $payload   = 'testing';
        $signature = $this->algorithm()->sign($payload, self::$rsaKeys['private']);

        $publicKey = openssl_pkey_get_public(self::$rsaKeys['public']->contents());
        assert($publicKey instanceof OpenSSLAsymmetricKey);

        self::assertSame(
            1,
            openssl_verify($payload, $signature, $publicKey, $this->signatureAlgorithm()),
        );
    }

    /** @test */
    public function signShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:' . PHP_EOL . '* error:');

        $this->algorithm()->sign('testing', InMemory::plainText('blablabla'));
    }

    /** @test */
    public function allOpenSSLErrorsShouldBeOnTheErrorMessage(): void
    {
        // Injects a random OpenSSL error message
        openssl_pkey_get_private('blahblah');

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageMatches('/^.* reason:(' . PHP_EOL . '\* error:.*){2,}/');

        $this->algorithm()->sign('testing', InMemory::plainText('blablabla'));
    }

    /** @test */
    public function signShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('The type of the provided key is not "RSA", "EC" provided');

        $this->algorithm()->sign('testing', self::$ecdsaKeys['private']);
    }

    /** @test */
    public function signShouldRaiseAnExceptionWhenKeyLengthIsBelowMinimum(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 2048 bits, only 512 bits provided');

        $this->algorithm()->sign('testing', self::$rsaKeys['private_short']);
    }

    /** @test */
    public function verifyShouldReturnTrueWhenSignatureIsValid(): void
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private(self::$rsaKeys['private']->contents());
        assert($privateKey instanceof OpenSSLAsymmetricKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, $this->signatureAlgorithm());

        self::assertTrue($this->algorithm()->verify($signature, $payload, self::$rsaKeys['public']));
    }

    /** @test */
    public function verifyShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:' . PHP_EOL . '* error:');

        $this->algorithm()->verify('testing', 'testing', InMemory::plainText('blablabla'));
    }

    /** @test */
    public function verifyShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key');

        $this->algorithm()->verify('testing', 'testing', self::$ecdsaKeys['private']);
    }
}
