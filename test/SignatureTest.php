<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

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
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->signer = $this->getMock(Signer::class);
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signature::__construct
     */
    public function constructorMustConfigureAttributes()
    {
        $signature = new Signature($this->signer, 'test');

        $this->assertAttributeSame($this->signer, 'signer', $signature);
        $this->assertAttributeEquals('test', 'hash', $signature);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signature::__construct
     *
     * @covers Lcobucci\JWT\Signature::__toString
     */
    public function toStringMustReturnTheHash()
    {
        $signature = new Signature($this->signer, 'test');

        $this->assertEquals('test', (string) $signature);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signature::__construct
     * @uses Lcobucci\JWT\Signature::__toString
     *
     * @covers Lcobucci\JWT\Signature::verify
     */
    public function verifyMustReturnTrueWhenHashMatches()
    {
        $this->signer->expects($this->any())
                     ->method('createHash')
                     ->willReturn('test');

        $signature = new Signature($this->signer, 'test');

        $this->assertTrue($signature->verify('one', 'key'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signature::__construct
     * @uses Lcobucci\JWT\Signature::__toString
     *
     * @covers Lcobucci\JWT\Signature::verify
     */
    public function verifyMustReturnFalseWhenHashDoesNotMatch()
    {
        $this->signer->expects($this->any())
                     ->method('createHash')
                     ->willReturn('testing');

        $signature = new Signature($this->signer, 'test');

        $this->assertFalse($signature->verify('one', 'key'));
    }
}
