<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Rsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA512;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Rsa\Sha512 */
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

        self::assertEquals('RS512', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::algorithm
     */
    public function algorithmMustBeCorrect(): void
    {
        $signer = new Sha512();

        self::assertEquals(OPENSSL_ALGO_SHA512, $signer->algorithm());
    }
}
