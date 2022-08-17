<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Rsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA384;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Rsa\UnsafeSha384 */
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

        self::assertEquals('RS384', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new UnsafeSha384();

        self::assertEquals(OPENSSL_ALGO_SHA384, $signer->algorithm());
    }
}
