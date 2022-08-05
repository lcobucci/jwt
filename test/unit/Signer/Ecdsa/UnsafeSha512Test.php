<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA512;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Ecdsa\UnsafeSha512 */
final class UnsafeSha512Test extends TestCase
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
        $signer = UnsafeSha512::create();

        self::assertInstanceOf(UnsafeSha512::class, $signer);
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
        self::assertSame('ES512', $this->getSigner()->algorithmId());
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
        self::assertSame(OPENSSL_ALGO_SHA512, $this->getSigner()->algorithm());
    }

    /**
     * @test
     *
     * @covers ::keyLength
     *
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa
     */
    public function keyLengthMustBeCorrect(): void
    {
        self::assertSame(132, $this->getSigner()->keyLength());
    }

    /**
     * @test
     *
     * @covers ::minimumBitsLengthForKey
     *
     * @uses \Lcobucci\JWT\Signer\UnsafeEcdsa::__construct
     */
    public function minimumBitsLengthForKeyMustBeCorrect(): void
    {
        self::assertSame(1, $this->getSigner()->minimumBitsLengthForKey());
    }

    private function getSigner(): UnsafeSha512
    {
        return new UnsafeSha512($this->createMock(SignatureConverter::class));
    }
}
