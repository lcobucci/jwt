<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Rsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA512;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Rsa\UnsafeSha512 */
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

        self::assertEquals('RS512', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new UnsafeSha512();

        self::assertEquals(OPENSSL_ALGO_SHA512, $signer->algorithm());
    }
}
