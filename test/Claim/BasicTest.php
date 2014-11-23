<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Claim;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 *
 * @coversDefaultClass Lcobucci\JWT\Claim\Basic
 */
class BasicTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     */
    public function constructorShouldConfigureTheAttributes()
    {
        $claim = new Basic('test', 1);

        $this->assertAttributeEquals('test', 'name', $claim);
        $this->assertAttributeEquals(1, 'value', $claim);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::getName
     */
    public function getNameShouldReturnTheClaimName()
    {
        $claim = new Basic('test', 1);

        $this->assertEquals('test', $claim->getName());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::getValue
     */
    public function getValueShouldReturnTheClaimValue()
    {
        $claim = new Basic('test', 1);

        $this->assertEquals(1, $claim->getValue());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::jsonSerialize
     */
    public function jsonSerializeShouldReturnTheClaimValue()
    {
        $claim = new Basic('test', 1);

        $this->assertEquals(1, $claim->jsonSerialize());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::__toString
     */
    public function toStringShouldReturnTheClaimValue()
    {
        $claim = new Basic('test', 1);

        $this->assertEquals('1', (string) $claim);
    }
}
