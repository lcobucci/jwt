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
 */
class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\Factory::__construct
     */
    public function constructMustConfigureTheCallbacks()
    {
        $callback = function() {};
        $factory = new Factory(['test' => $callback]);

        $expected = [
            'HS256' => [$factory, 'createHmacSha256'],
            'HS384' => [$factory, 'createHmacSha384'],
            'HS512' => [$factory, 'createHmacSha512'],
            'test' => $callback
        ];

        $this->assertAttributeEquals($expected, 'callbacks', $factory);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createHmacSha256
     */
    public function createMustBeAbleReturnASha256Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(Sha256::class, $factory->create('HS256'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createHmacSha384
     */
    public function createMustBeAbleReturnASha384Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(Sha384::class, $factory->create('HS384'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createHmacSha512
     */
    public function createMustBeAbleReturnASha512Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(Sha512::class, $factory->create('HS512'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     *
     * @expectedException InvalidArgumentException
     */
    public function createMustRaiseExceptionWhenIdIsInvalid()
    {
        $factory = new Factory();
        $factory->create('testing');
    }
}
