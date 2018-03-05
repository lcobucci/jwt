<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

final class Sha384Test extends BaseTestCase
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
        self::assertInstanceOf(Sha384::class, Sha384::create());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha384::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        self::assertEquals('ES384', $this->getSigner()->getAlgorithmId());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha384::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        self::assertEquals('sha384', $this->getSigner()->getAlgorithm());
    }

    private function getSigner(): Sha384
    {
        return new Sha384($this->adapter, $this->keyParser);
    }
}
