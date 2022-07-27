<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Hmac\UnsafeSha512 */
final class UnsafeSha512Test extends TestCase
{
    /**
     * @test
     *
     * @covers ::algorithmId
     */
    public function algorithmIdMustBeCorrect(): void
    {
        $signer = new UnsafeSha512();

        self::assertEquals('HS512', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new UnsafeSha512();

        self::assertEquals('sha512', $signer->algorithm());
    }

    /**
     * @test
     *
     * @covers ::minimumBitsLengthForKey
     */
    public function minimumBytesLengthForKeyIsWhatItIs(): void
    {
        $signer = new UnsafeSha512();

        self::assertSame(1, $signer->minimumBitsLengthForKey());
    }
}
