<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

use function assert;
use function is_resource;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

use const OPENSSL_ALGO_SHA256;

/** @coversDefaultClass \Lcobucci\JWT\Signer\UnsafeEcdsa */
final class UnsafeEcdsaTest extends TestCase
{
    use Keys;

    private MultibyteStringConverter $pointsManipulator;

    /** @before */
    public function createDependencies(): void
    {
        $this->pointsManipulator = new MultibyteStringConverter();
    }

    private function getSigner(): UnsafeEcdsa
    {
        $signer = $this->getMockForAbstractClass(UnsafeEcdsa::class, [$this->pointsManipulator]);

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
     * @covers \Lcobucci\JWT\Signer\UnsafeEcdsa::minimumBitsLengthForKey
     * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     *
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa::__construct
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
     * @covers \Lcobucci\JWT\Signer\UnsafeEcdsa::minimumBitsLengthForKey
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa::__construct
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa::verify
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldAcceptAKeyLengthBelowMinimum(): void
    {
        $signer = $this->getSigner();

        $payload   = 'testing';
        $signature = $signer->sign($payload, self::$ecdsaKeys['private_short']);

        self::assertTrue($signer->verify($signature, $payload, self::$ecdsaKeys['public_short']));
    }

    /**
     * @test
     *
     * @covers ::verify
     * @covers ::keyType
     * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     *
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa::__construct
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa::minimumBitsLengthForKey
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
