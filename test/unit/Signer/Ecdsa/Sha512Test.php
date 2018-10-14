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
     * @uses \Lcobucci\JWT\Signer\Ecdsa\Asn1
     */
    public function createShouldReturnAValidInstance(): void
    {
        $signer = Sha512::create();

        self::assertInstanceOf(Sha512::class, $signer);
        self::assertAttributeInstanceOf(Asn1::class, 'manipulator', $signer);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        self::assertSame('ES512', $this->getSigner()->getAlgorithmId());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        self::assertSame(OPENSSL_ALGO_SHA512, $this->getSigner()->getAlgorithm());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512::getKeyLength
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
