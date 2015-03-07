<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as EcdsaSha384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as EcdsaSha512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HmacSha384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HmacSha512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RsaSha512;

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
        $callback = function () {
        };
        $factory = new Factory(['test' => $callback]);

        $expected = [
            'HS256' => [$factory, 'createHmacSha256'],
            'HS384' => [$factory, 'createHmacSha384'],
            'HS512' => [$factory, 'createHmacSha512'],
            'RS256' => [$factory, 'createRsaSha256'],
            'RS384' => [$factory, 'createRsaSha384'],
            'RS512' => [$factory, 'createRsaSha512'],
            'ES256' => [$factory, 'createEcdsaSha256'],
            'ES384' => [$factory, 'createEcdsaSha384'],
            'ES512' => [$factory, 'createEcdsaSha512'],
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
    public function createMustBeAbleReturnAHmacSha256Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(HmacSha256::class, $factory->create('HS256'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createHmacSha384
     */
    public function createMustBeAbleReturnAHmacSha384Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(HmacSha384::class, $factory->create('HS384'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createHmacSha512
     */
    public function createMustBeAbleReturnAHmacSha512Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(HmacSha512::class, $factory->create('HS512'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createRsaSha256
     */
    public function createMustBeAbleReturnARsaSha256Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(RsaSha256::class, $factory->create('RS256'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createRsaSha384
     */
    public function createMustBeAbleReturnARsaSha384Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(RsaSha384::class, $factory->create('RS384'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createRsaSha512
     */
    public function createMustBeAbleReturnARsaSha512Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(RsaSha512::class, $factory->create('RS512'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createEcdsaSha256
     */
    public function createMustBeAbleReturnAEcdsaSha256Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(EcdsaSha256::class, $factory->create('ES256'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createEcdsaSha384
     */
    public function createMustBeAbleReturnAEcdsaSha384Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(EcdsaSha384::class, $factory->create('ES384'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     *
     * @covers Lcobucci\JWT\Signer\Factory::create
     * @covers Lcobucci\JWT\Signer\Factory::createEcdsaSha512
     */
    public function createMustBeAbleReturnAEcdsaSha512Signer()
    {
        $factory = new Factory();

        $this->assertInstanceOf(EcdsaSha512::class, $factory->create('ES512'));
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
