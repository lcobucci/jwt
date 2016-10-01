<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Key;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class SignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Signer|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $signer;

    /**
     * @before
     */
    public function initializeDependencies()
    {
        $this->signer = $this->createMock(Signer::class);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signature::__construct
     */
    public function constructorMustConfigureAttributes()
    {
        $signature = new Signature('test');

        self::assertAttributeEquals('test', 'hash', $signature);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signature::__construct
     *
     * @covers \Lcobucci\JWT\Signature::__toString
     */
    public function toStringMustReturnTheHash()
    {
        $signature = new Signature('test');

        self::assertEquals('test', (string) $signature);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signature::__construct
     * @uses \Lcobucci\JWT\Signature::__toString
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signature::verify
     */
    public function verifyMustReturnWhatSignerSays()
    {
        $this->signer->expects($this->any())
                     ->method('verify')
                     ->willReturn(true);

        $signature = new Signature('test');

        self::assertTrue($signature->verify($this->signer, 'one', new Key('key')));
    }
}
