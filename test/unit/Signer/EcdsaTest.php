<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use PHPUnit\Framework\TestCase;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;
use const OPENSSL_ALGO_SHA256;

final class EcdsaTest extends TestCase
{
    use Keys;

    private MultibyteStringConverter $pointsManipulator;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->pointsManipulator = new MultibyteStringConverter();
    }

    private function getSigner(): Ecdsa
    {
        $signer = $this->getMockForAbstractClass(Ecdsa::class, [$this->pointsManipulator]);

        $signer->method('getAlgorithm')
               ->willReturn(OPENSSL_ALGO_SHA256);

        $signer->method('getAlgorithmId')
               ->willReturn('ES256');

        $signer->method('getKeyLength')
               ->willReturn(64);

        return $signer;
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa::sign
     * @covers \Lcobucci\JWT\Signer\Ecdsa::getKeyType
     * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function signShouldReturnTheAHashBasedOnTheOpenSslSignature(): void
    {
        $payload = 'testing';

        $signer    = $this->getSigner();
        $signature = $signer->sign($payload, self::$ecdsaKeys['private']);

        $publicKey = openssl_pkey_get_public(self::$ecdsaKeys['public1']->getContent());

        self::assertIsResource($publicKey);
        self::assertSame(
            1,
            openssl_verify(
                $payload,
                $this->pointsManipulator->toAsn1($signature, $signer->getKeyLength()),
                $publicKey,
                OPENSSL_ALGO_SHA256
            )
        );
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa::verify
     * @covers \Lcobucci\JWT\Signer\Ecdsa::getKeyType
     * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function verifyShouldDelegateToEcdsaSignerUsingPublicKey(): void
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private(self::$ecdsaKeys['private']->getContent());

        self::assertIsResource($privateKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $signer = $this->getSigner();

        self::assertTrue(
            $signer->verify(
                $this->pointsManipulator->fromAsn1($signature, $signer->getKeyLength()),
                $payload,
                self::$ecdsaKeys['public1']
            )
        );
    }
}
