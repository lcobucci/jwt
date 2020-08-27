<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Rsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA256;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Rsa\Sha256 */
final class Sha256Test extends TestCase
{
    /**
     * @test
     *
     * @covers ::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        $signer = new Sha256();

        self::assertEquals('RS256', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers ::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        $signer = new Sha256();

        self::assertEquals(OPENSSL_ALGO_SHA256, $signer->getAlgorithm());
    }
}
