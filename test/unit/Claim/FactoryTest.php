<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Claim;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Claim\Factory::__construct
     */
    public function constructMustConfigureTheCallbacks()
    {
        $callback = function () {
        };
        $factory = new Factory(['test' => $callback]);

        $expected = [
            'iat' => [$factory, 'createLesserOrEqualsTo'],
            'nbf' => [$factory, 'createLesserOrEqualsTo'],
            'exp' => [$factory, 'createGreaterOrEqualsTo'],
            'iss' => [$factory, 'createContainedEqualsTo'],
            'aud' => [$factory, 'createContainsEqualsTo'],
            'sub' => [$factory, 'createEqualsTo'],
            'jti' => [$factory, 'createEqualsTo'],
            'test' => $callback
        ];

        self::assertAttributeEquals($expected, 'callbacks', $factory);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Factory::__construct
     * @uses \Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers \Lcobucci\JWT\Claim\Factory::create
     * @covers \Lcobucci\JWT\Claim\Factory::createLesserOrEqualsTo
     */
    public function createShouldReturnALesserOrEqualsToClaimForIssuedAt()
    {
        $claim = new Factory();

        self::assertInstanceOf(LesserOrEqualsTo::class, $claim->create('iat', 1));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Factory::__construct
     * @uses \Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers \Lcobucci\JWT\Claim\Factory::create
     * @covers \Lcobucci\JWT\Claim\Factory::createLesserOrEqualsTo
     */
    public function createShouldReturnALesserOrEqualsToClaimForNotBefore()
    {
        $claim = new Factory();

        self::assertInstanceOf(LesserOrEqualsTo::class, $claim->create('nbf', 1));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Factory::__construct
     * @uses \Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers \Lcobucci\JWT\Claim\Factory::create
     * @covers \Lcobucci\JWT\Claim\Factory::createGreaterOrEqualsTo
     */
    public function createShouldReturnAGreaterOrEqualsToClaimForExpiration()
    {
        $claim = new Factory();

        self::assertInstanceOf(GreaterOrEqualsTo::class, $claim->create('exp', 1));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Factory::__construct
     * @uses \Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers \Lcobucci\JWT\Claim\Factory::create
     * @covers \Lcobucci\JWT\Claim\Factory::createEqualsTo
     */
    public function createShouldReturnAnEqualsToClaimForId()
    {
        $claim = new Factory();

        self::assertInstanceOf(EqualsTo::class, $claim->create('jti', 1));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Factory::__construct
     * @uses \Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers \Lcobucci\JWT\Claim\Factory::create
     * @covers \Lcobucci\JWT\Claim\Factory::createContainedEqualsTo
     */
    public function createShouldReturnAContainedEqualsToClaimForIssuer()
    {
        $claim = new Factory();

        self::assertInstanceOf(ContainedEqualsTo::class, $claim->create('iss', 1));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Factory::__construct
     * @uses \Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers \Lcobucci\JWT\Claim\Factory::create
     * @covers \Lcobucci\JWT\Claim\Factory::createContainsEqualsTo
     */
    public function createShouldReturnAContainsEqualsToClaimForAudience()
    {
        $claim = new Factory();

        self::assertInstanceOf(ContainsEqualsTo::class, $claim->create('aud', 1));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Factory::__construct
     * @uses \Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers \Lcobucci\JWT\Claim\Factory::create
     * @covers \Lcobucci\JWT\Claim\Factory::createEqualsTo
     */
    public function createShouldReturnAnEqualsToClaimForSubject()
    {
        $claim = new Factory();

        self::assertInstanceOf(EqualsTo::class, $claim->create('sub', 1));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Factory::__construct
     * @uses \Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers \Lcobucci\JWT\Claim\Factory::create
     * @covers \Lcobucci\JWT\Claim\Factory::createBasic
     */
    public function createShouldReturnABasiclaimForOtherClaims()
    {
        $claim = new Factory();

        self::assertInstanceOf(Basic::class, $claim->create('test', 1));
    }
}
