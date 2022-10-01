<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Hmac\Sha512 */
final class Sha512Test extends TestCase
{
    /**
     * @test
     *
     * @covers ::algorithmId
     */
    public function algorithmIdMustBeCorrect(): void
    {
        $signer = new Sha512();

        self::assertSame('HS512', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new Sha512();

        self::assertSame('sha512', $signer->algorithm());
    }

    /**
     * @test
     *
     * @covers ::minimumBitsLengthForKey
     */
    public function minimumBitsLengthForKeyMustBeCorrect(): void
    {
        $signer = new Sha512();

        self::assertSame(512, $signer->minimumBitsLengthForKey());
    }
}
