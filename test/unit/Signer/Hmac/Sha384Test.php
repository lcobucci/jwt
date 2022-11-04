<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Hmac\Sha384 */
final class Sha384Test extends TestCase
{
    /**
     * @test
     *
     * @covers ::algorithmId
     */
    public function algorithmIdMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertSame('HS384', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertSame('sha384', $signer->algorithm());
    }

    /**
     * @test
     *
     * @covers ::minimumBitsLengthForKey
     */
    public function minimumBitsLengthForKeyMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertSame(384, $signer->minimumBitsLengthForKey());
    }
}
