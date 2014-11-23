<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Hmac\Sha512;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 *
 * @coversDefaultClass Lcobucci\JWT\Signer\Factory
 */
class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @covers ::__construct
     * @covers ::create
     * @covers ::createHmacSha256
     */
    public function createMustBeAbleReturnASha256Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(Sha256::class, $factory->create('HS256'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::create
     * @covers ::createHmacSha384
     */
    public function createMustBeAbleReturnASha384Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(Sha384::class, $factory->create('HS384'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::create
     * @covers ::createHmacSha512
     */
    public function createMustBeAbleReturnASha512Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(Sha512::class, $factory->create('HS512'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::create
     *
     * @expectedException InvalidArgumentException
     */
    public function createMustRaiseExceptionWhenIdIsInvalid()
    {
        $factory = new Factory();
        $factory->create('testing');
    }
}
