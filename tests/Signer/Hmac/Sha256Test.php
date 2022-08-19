<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Hmac;

use Lcobucci\JWT\Signer\Hmac\Sha256;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Hmac\Sha256 */
final class Sha256Test extends TestCase
{
    /**
     * @test
     *
     * @covers ::algorithmId
     */
    public function algorithmIdMustBeCorrect(): void
    {
        $signer = new Sha256();

        self::assertSame('HS256', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new Sha256();

        self::assertSame('sha256', $signer->algorithm());
    }

    /**
     * @test
     *
     * @covers ::minimumBitsLengthForKey
     */
    public function minimumBitsLengthForKeyMustBeCorrect(): void
    {
        $signer = new Sha256();

        self::assertSame(256, $signer->minimumBitsLengthForKey());
    }
}
