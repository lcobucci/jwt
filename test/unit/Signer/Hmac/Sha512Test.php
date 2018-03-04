<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

use PHPUnit\Framework\TestCase;

final class Sha512Test extends TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha512::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        $signer = new Sha512();

        self::assertEquals('HS512', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha512::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        $signer = new Sha512();

        self::assertEquals('sha512', $signer->getAlgorithm());
    }
}
