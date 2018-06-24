<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;
use const OPENSSL_ALGO_SHA256;

final class Sha256Test extends TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa::create
     * @covers \Lcobucci\JWT\Signer\Ecdsa::__construct
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\Asn1
     */
    public function createShouldReturnAValidInstance(): void
    {
        $signer = Sha256::create();

        self::assertInstanceOf(Sha256::class, $signer);
        self::assertAttributeInstanceOf(Asn1::class, 'manipulator', $signer);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        self::assertSame('ES256', $this->getSigner()->getAlgorithmId());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        self::assertSame(OPENSSL_ALGO_SHA256, $this->getSigner()->getAlgorithm());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256::getKeyLength
     */
    public function getKeyLengthMustBeCorrect(): void
    {
        self::assertSame(64, $this->getSigner()->getKeyLength());
    }

    private function getSigner(): Sha256
    {
        return new Sha256($this->createMock(PointsManipulator::class));
    }
}
