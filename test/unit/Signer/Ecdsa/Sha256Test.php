<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
final class Sha256Test extends BaseTestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa::create
     * @covers \Lcobucci\JWT\Signer\Ecdsa::__construct
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @uses \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @uses \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     */
    public function createShouldReturnAValidInstance(): void
    {
        self::assertInstanceOf(Sha256::class, Sha256::create());
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
        self::assertEquals('ES256', $this->getSigner()->getAlgorithmId());
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
        self::assertEquals('sha256', $this->getSigner()->getAlgorithm());
    }

    private function getSigner(): Sha256
    {
        return new Sha256($this->adapter, $this->keyParser);
    }
}
