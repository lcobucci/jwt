<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Tests\Keys;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function assert;
use function openssl_error_string;

abstract class RsaPssTestCase extends TestCase
{
    use Keys;

    abstract protected function algorithm(): RsaPss;

    abstract protected function algorithmId(): string;

    abstract protected function signatureAlgorithm(): string;

    #[PHPUnit\After]
    final public function clearOpenSSLErrors(): void
    {
        // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        while (openssl_error_string()) {
        }
    }

    #[PHPUnit\Test]
    final public function algorithmIdMustBeCorrect(): void
    {
        self::assertSame($this->algorithmId(), $this->algorithm()->algorithmId());
    }

    #[PHPUnit\Test]
    final public function signatureAlgorithmMustBeCorrect(): void
    {
        self::assertSame($this->signatureAlgorithm(), $this->algorithm()->algorithm());
    }

    #[PHPUnit\Test]
    public function signShouldReturnAValidOpensslSignature(): void
    {
        $payload   = 'testing';
        $signature = $this->algorithm()->sign($payload, self::$rsaKeys['private']);

        $publicKey = PublicKeyLoader::loadPublicKey(self::$rsaKeys['public']->contents());
        assert($publicKey instanceof RSA\PublicKey);

        self::assertTrue(
            $publicKey
                ->withHash($this->signatureAlgorithm())
                ->withMGFHash($this->signatureAlgorithm())
                ->verify($payload, $signature),
        );
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason: ');

        $this->algorithm()->sign('testing', InMemory::plainText('blablabla'));
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage(
            'The type of the provided key is not "RSA", "phpseclib3\Crypt\EC\PrivateKey" provided',
        );

        $this->algorithm()->sign('testing', self::$ecdsaKeys['private']);
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyLengthIsBelowMinimum(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 2048 bits, only 512 bits provided');

        $this->algorithm()->sign('testing', self::$rsaKeys['private_short']);
    }

    #[PHPUnit\Test]
    public function verifyShouldReturnTrueWhenSignatureIsValid(): void
    {
        $payload    = 'testing';
        $privateKey = PublicKeyLoader::loadPrivateKey(self::$rsaKeys['private']->contents());
        assert($privateKey instanceof RSA\PrivateKey);

        $signature = $privateKey
            ->withHash($this->signatureAlgorithm())
            ->withMGFHash($this->signatureAlgorithm())
            ->sign($payload);

        self::assertTrue($this->algorithm()->verify($signature, $payload, self::$rsaKeys['public']));
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:');

        $this->algorithm()->verify('testing', 'testing', InMemory::plainText('blablabla'));
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage(
            'The type of the provided key is not "RSA", "phpseclib3\Crypt\EC\PublicKey" provided',
        );

        $this->algorithm()->verify('testing', 'testing', self::$ecdsaKeys['public1']);
    }
}
