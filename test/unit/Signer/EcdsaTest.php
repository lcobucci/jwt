<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

use function assert;
use function is_resource;
use function openssl_error_string;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

use const OPENSSL_ALGO_SHA256;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Ecdsa */
final class EcdsaTest extends TestCase
{
    use Keys;

    private MultibyteStringConverter $pointsManipulator;

    /** @after */
    public function clearOpenSSLErrors(): void
    {
        // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        while (openssl_error_string()) {
        }
    }

    /** @before */
    public function createDependencies(): void
    {
        $this->pointsManipulator = new MultibyteStringConverter();
    }

    private function getSigner(): Ecdsa
    {
        $signer = $this->getMockForAbstractClass(Ecdsa::class, [$this->pointsManipulator]);

        $signer->method('algorithm')
               ->willReturn(OPENSSL_ALGO_SHA256);

        $signer->method('algorithmId')
               ->willReturn('ES256');

        $signer->method('pointLength')
               ->willReturn(64);

        return $signer;
    }

    /**
     * @test
     *
     * @covers ::sign
     * @covers ::keyType
     * @covers \Lcobucci\JWT\Signer\Ecdsa::minimumBitsLengthForKey
     * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldReturnTheAHashBasedOnTheOpenSslSignature(): void
    {
        $payload = 'testing';

        $signer    = $this->getSigner();
        $signature = $signer->sign($payload, self::$ecdsaKeys['private']);

        $publicKey = openssl_pkey_get_public(self::$ecdsaKeys['public1']->contents());
        assert(is_resource($publicKey) || $publicKey instanceof OpenSSLAsymmetricKey);

        self::assertSame(
            1,
            openssl_verify(
                $payload,
                $this->pointsManipulator->toAsn1($signature, $signer->pointLength()),
                $publicKey,
                OPENSSL_ALGO_SHA256
            )
        );
    }

    /**
     * @test
     *
     * @requires extension openssl < 3.0
     *
     * @covers ::sign
     * @covers ::keyType
     * @covers \Lcobucci\JWT\Signer\Ecdsa::minimumBitsLengthForKey
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldRaiseAnExceptionWhenKeyLengthIsBelowMinimum(): void
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 224 bits, only 161 bits provided');

        $signer->sign('testing', self::$ecdsaKeys['private_short']);
    }

    /**
     * @test
     *
     * @covers ::verify
     * @covers ::keyType
     * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Lcobucci\JWT\Signer\Ecdsa::minimumBitsLengthForKey
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldDelegateToEcdsaSignerUsingPublicKey(): void
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private(self::$ecdsaKeys['private']->contents());
        assert(is_resource($privateKey) || $privateKey instanceof OpenSSLAsymmetricKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $signer = $this->getSigner();

        self::assertTrue(
            $signer->verify(
                $this->pointsManipulator->fromAsn1($signature, $signer->pointLength()),
                $payload,
                self::$ecdsaKeys['public1']
            )
        );
    }
}
