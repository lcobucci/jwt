<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA256;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Ecdsa\UnsafeSha256 */
final class UnsafeSha256Test extends TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\UnsafeEcdsa::create
     * @covers \Lcobucci\JWT\Signer\UnsafeEcdsa::__construct
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     */
    public function createShouldReturnAValidInstance(): void
    {
        $signer = UnsafeSha256::create();

        self::assertInstanceOf(UnsafeSha256::class, $signer);
    }

    /**
     * @test
     *
     * @covers ::algorithmId
     *
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa
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
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa
     */
    public function algorithmMustBeCorrect(): void
    {
        self::assertSame(OPENSSL_ALGO_SHA256, $this->getSigner()->algorithm());
    }

    /**
     * @test
     *
     * @covers ::pointLength
     *
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa
     */
    public function keyLengthMustBeCorrect(): void
    {
        self::assertSame(64, $this->getSigner()->pointLength());
    }

    private function getSigner(): UnsafeSha256
    {
        return new UnsafeSha256($this->createMock(SignatureConverter::class));
    }
}
