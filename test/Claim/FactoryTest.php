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
 * @coversDefaultClass Lcobucci\JWT\Claim\Factory
 */
class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::create
     * @covers ::createLesserOrEqualsTo
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     */
    public function createShouldReturnALesserOrEqualsToClaimForIssuedAt()
    {
        $claim = new Factory();

        $this->assertInstanceOf(LesserOrEqualsTo::class, $claim->create('iat', 1));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::create
     * @covers ::createLesserOrEqualsTo
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     */
    public function createShouldReturnALesserOrEqualsToClaimForNotBefore()
    {
        $claim = new Factory();

        $this->assertInstanceOf(LesserOrEqualsTo::class, $claim->create('nbf', 1));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::create
     * @covers ::createGreaterOrEqualsTo
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     */
    public function createShouldReturnAGreaterOrEqualsToClaimForExpiration()
    {
        $claim = new Factory();

        $this->assertInstanceOf(GreaterOrEqualsTo::class, $claim->create('exp', 1));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::create
     * @covers ::createEqualsTo
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     */
    public function createShouldReturnAnEqualsToClaimForId()
    {
        $claim = new Factory();

        $this->assertInstanceOf(EqualsTo::class, $claim->create('jti', 1));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::create
     * @covers ::createEqualsTo
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     */
    public function createShouldReturnAnEqualsToClaimForIssuer()
    {
        $claim = new Factory();

        $this->assertInstanceOf(EqualsTo::class, $claim->create('iss', 1));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::create
     * @covers ::createEqualsTo
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     */
    public function createShouldReturnAnEqualsToClaimForAudience()
    {
        $claim = new Factory();

        $this->assertInstanceOf(EqualsTo::class, $claim->create('aud', 1));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::create
     * @covers ::createEqualsTo
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     */
    public function createShouldReturnAnEqualsToClaimForSubject()
    {
        $claim = new Factory();

        $this->assertInstanceOf(EqualsTo::class, $claim->create('sub', 1));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::create
     * @covers ::createBasic
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     */
    public function createShouldReturnABasiclaimForOtherClaims()
    {
        $claim = new Factory();

        $this->assertInstanceOf(Basic::class, $claim->create('test', 1));
    }
}
