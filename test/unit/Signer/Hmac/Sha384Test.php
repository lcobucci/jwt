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
     * @covers ::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertEquals('HS384', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers ::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertEquals('sha384', $signer->getAlgorithm());
    }
}
