<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Rsa;

use PHPUnit\Framework\TestCase;

use const OPENSSL_ALGO_SHA384;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Rsa\Sha384 */
final class Sha384Test extends TestCase
{
    /**
     * @test
     *
     * @covers ::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertEquals('RS384', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers ::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertEquals(OPENSSL_ALGO_SHA384, $signer->getAlgorithm());
    }
}
