<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;
use const OPENSSL_ALGO_SHA384;

final class Sha384Test extends TestCase
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
        $signer = Sha384::create();

        self::assertInstanceOf(Sha384::class, $signer);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha384::getAlgorithmId
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        self::assertSame('ES384', $this->getSigner()->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha384::getAlgorithm
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        self::assertSame(OPENSSL_ALGO_SHA384, $this->getSigner()->getAlgorithm());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha384::getKeyLength
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function getKeyLengthMustBeCorrect(): void
    {
        self::assertSame(96, $this->getSigner()->getKeyLength());
    }

    private function getSigner(): Sha384
    {
        return new Sha384($this->createMock(PointsManipulator::class));
    }
}
