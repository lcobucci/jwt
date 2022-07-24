<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Hmac\UnsafeSha384 */
final class UnsafeSha384Test extends TestCase
{
    /**
     * @test
     *
     * @covers ::algorithmId
     */
    public function algorithmIdMustBeCorrect(): void
    {
        $signer = new UnsafeSha384();

        self::assertEquals('HS384', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new UnsafeSha384();

        self::assertEquals('sha384', $signer->algorithm());
    }

    /**
     * @test
     *
     * @covers ::minimumBytesLengthForKey
     */
    public function minimumBytesLengthForKeyIsWhatItIs(): void
    {
        $signer = new UnsafeSha384();

        self::assertSame(1, $signer->minimumBytesLengthForKey());
    }
}
