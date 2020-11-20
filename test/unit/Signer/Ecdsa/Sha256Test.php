<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA256;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Ecdsa\Sha256 */
final class Sha256Test extends TestCase
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
        $signer = Sha256::create();

        self::assertInstanceOf(Sha256::class, $signer);
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
        self::assertSame('ES256', $this->getSigner()->algorithmId());
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
        self::assertSame(OPENSSL_ALGO_SHA256, $this->getSigner()->algorithm());
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
        self::assertSame(64, $this->getSigner()->keyLength());
    }

    private function getSigner(): Sha256
    {
        return new Sha256($this->createMock(SignatureConverter::class));
    }
}
