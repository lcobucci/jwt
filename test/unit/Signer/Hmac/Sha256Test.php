<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

use PHPUnit\Framework\TestCase;

final class Sha256Test extends TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha256::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        $signer = new Sha256();

        self::assertEquals('HS256', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha256::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        $signer = new Sha256();

        self::assertEquals('sha256', $signer->getAlgorithm());
    }
}
