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
     * @uses \Lcobucci\JWT\Signer\Ecdsa\ECSignature
     */
    public function createShouldReturnAValidInstance(): void
    {
        $signer = Sha256::create();

        self::assertInstanceOf(Sha256::class, $signer);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256::getAlgorithmId
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        self::assertSame('ES256', $this->getSigner()->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256::getAlgorithm
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        self::assertSame(OPENSSL_ALGO_SHA256, $this->getSigner()->getAlgorithm());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256::getKeyLength
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
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
