<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Hmac;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class Sha384Test extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha384::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertEquals('HS384', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha384::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect(): void
    {
        $signer = new Sha384();

        self::assertEquals('sha384', $signer->getAlgorithm());
    }
}
