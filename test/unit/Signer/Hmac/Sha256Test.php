<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

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

        self::assertEquals('HS256', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        $signer = new Sha256();

        self::assertEquals('sha256', $signer->getAlgorithm());
    }
}
