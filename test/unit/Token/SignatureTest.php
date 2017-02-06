<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class SignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Signature::__construct
     * @covers \Lcobucci\JWT\Token\Signature::fromEmptyData
     */
    public function fromEmptyDataShouldReturnAnEmptySignature(): void
    {
        $signature = Signature::fromEmptyData();

        self::assertAttributeEmpty('hash', $signature);
        self::assertAttributeEmpty('encoded', $signature);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Signature::__construct
     * @covers \Lcobucci\JWT\Token\Signature::hash
     */
    public function hashShouldReturnTheHash(): void
    {
        $signature = new Signature('test', 'encoded');

        self::assertEquals('test', $signature->hash());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Signature::__construct
     * @covers \Lcobucci\JWT\Token\Signature::__toString
     */
    public function toStringMustReturnTheEncodedData(): void
    {
        $signature = new Signature('test', 'encoded');

        self::assertEquals('encoded', (string) $signature);
    }
}
