<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Hmac\UnsafeSha256 */
final class UnsafeSha256Test extends TestCase
{
    /**
     * @test
     *
     * @covers ::algorithmId
     */
    public function algorithmIdMustBeCorrect(): void
    {
        $signer = new UnsafeSha256();

        self::assertEquals('HS256', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new UnsafeSha256();

        self::assertEquals('sha256', $signer->algorithm());
    }

    /**
     * @test
     *
     * @covers ::minimumBytesLengthForKey
     */
    public function minimumBytesLengthForKeyIsWhatItIs(): void
    {
        $signer = new UnsafeSha256();

        self::assertSame(1, $signer->minimumBytesLengthForKey());
    }
}
