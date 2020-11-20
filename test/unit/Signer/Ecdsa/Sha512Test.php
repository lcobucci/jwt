<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA512;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Ecdsa\Sha512 */
final class Sha512Test extends TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa::create
     * @covers \Lcobucci\JWT\Signer\Ecdsa::__construct
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     */
    public function createShouldReturnAValidInstance(): void
    {
        $signer = Sha512::create();

        self::assertInstanceOf(Sha512::class, $signer);
    }

    /**
     * @test
     *
     * @covers ::algorithmId
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function algorithmIdMustBeCorrect(): void
    {
        self::assertSame('ES512', $this->getSigner()->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function algorithmMustBeCorrect(): void
    {
        self::assertSame(OPENSSL_ALGO_SHA512, $this->getSigner()->algorithm());
    }

    /**
     * @test
     *
     * @covers ::keyLength
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa
     */
    public function keyLengthMustBeCorrect(): void
    {
        self::assertSame(132, $this->getSigner()->keyLength());
    }

    private function getSigner(): Sha512
    {
        return new Sha512($this->createMock(SignatureConverter::class));
    }
}
