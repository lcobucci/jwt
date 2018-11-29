<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;
use const OPENSSL_ALGO_SHA512;

final class Sha512Test extends TestCase
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
        $signer = Sha512::create();

        self::assertInstanceOf(Sha512::class, $signer);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512::getAlgorithmId
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        self::assertSame('ES512', $this->getSigner()->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512::getAlgorithm
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        self::assertSame(OPENSSL_ALGO_SHA512, $this->getSigner()->getAlgorithm());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512::getKeyLength
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function getKeyLengthMustBeCorrect(): void
    {
        self::assertSame(132, $this->getSigner()->getKeyLength());
    }

    private function getSigner(): Sha512
    {
        return new Sha512($this->createMock(PointsManipulator::class));
    }
}
