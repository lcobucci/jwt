<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Rsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA256;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Rsa\UnsafeSha256 */
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

        self::assertEquals('RS256', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new UnsafeSha256();

        self::assertEquals(OPENSSL_ALGO_SHA256, $signer->algorithm());
    }

    /**
     * @test
     *
     * @covers ::minimumBitsLengthForKey
     */
    public function minimumBitsLengthForKeyMustBeCorrect(): void
    {
        $signer = new UnsafeSha256();

        self::assertSame(1, $signer->minimumBitsLengthForKey());
    }
}
