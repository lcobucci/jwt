<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Tests\Keys;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

use function assert;
use function openssl_error_string;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

abstract class EcdsaTestCase extends TestCase
{
    use Keys;

    protected MultibyteStringConverter $pointsManipulator;

    /** @after */
    final public function clearOpenSSLErrors(): void
    {
        // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        while (openssl_error_string()) {
        }
    }

    /** @before */
    final public function createDependencies(): void
    {
        $this->pointsManipulator = new MultibyteStringConverter();
    }

    abstract protected function algorithm(): Ecdsa;

    abstract protected function algorithmId(): string;

    abstract protected function signatureAlgorithm(): int;

    abstract protected function pointLength(): int;

    abstract protected function keyLength(): int;

    abstract protected function verificationKey(): Key;

    abstract protected function signingKey(): Key;

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
    final public function pointLengthMustBeCorrect(): void
    {
        self::assertSame($this->pointLength(), $this->algorithm()->pointLength());
    }

    /** @test */
    final public function expectedKeyLengthMustBeCorrect(): void
    {
        self::assertSame($this->keyLength(), $this->algorithm()->expectedKeyLength());
    }

    /** @test */
    public function signShouldReturnTheAHashBasedOnTheOpenSslSignature(): void
    {
        $payload = 'testing';

        $signer    = $this->algorithm();
        $signature = $signer->sign($payload, $this->signingKey());

        $publicKey = openssl_pkey_get_public($this->verificationKey()->contents());
        assert($publicKey instanceof OpenSSLAsymmetricKey);

        self::assertSame(
            1,
            openssl_verify(
                $payload,
                $this->pointsManipulator->toAsn1($signature, $signer->pointLength()),
                $publicKey,
                $this->signatureAlgorithm(),
            ),
        );
    }

    /**
     * @test
     * @dataProvider incompatibleKeys
     */
    public function signShouldRaiseAnExceptionWhenKeyLengthIsNotTheExpectedOne(
        string $keyId,
        int $keyLength,
    ): void {
        self::assertArrayHasKey($keyId, self::$ecdsaKeys);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage(
            'The length of the provided key is different than ' . $this->keyLength()
            . ' bits, ' . $keyLength . ' bits provided',
        );

        $this->algorithm()->sign('testing', self::$ecdsaKeys[$keyId]);
    }

    /** @return iterable<string, array{string, int}> */
    abstract public static function incompatibleKeys(): iterable;

    /** @test */
    public function signShouldRaiseAnExceptionWhenKeyTypeIsNotEC(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('The type of the provided key is not "EC", "RSA" provided');

        $this->algorithm()->sign('testing', self::$rsaKeys['private']);
    }

    /** @test */
    public function verifyShouldDelegateToEcdsaSignerUsingPublicKey(): void
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private($this->signingKey()->contents());
        assert($privateKey instanceof OpenSSLAsymmetricKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, $this->signatureAlgorithm());

        $signer = $this->algorithm();

        self::assertTrue(
            $signer->verify(
                $this->pointsManipulator->fromAsn1($signature, $signer->pointLength()),
                $payload,
                $this->verificationKey(),
            ),
        );
    }
}
