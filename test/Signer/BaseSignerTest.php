<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signature;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class BaseSignerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var BaseSigner|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $signer;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->signer = $this->getMockForAbstractClass(BaseSigner::class);

        $this->signer->expects($this->any())
                     ->method('getAlgorithmId')
                     ->willReturn('TEST123');

        $this->signer->expects($this->any())
                     ->method('createHash')
                     ->willReturn('test');
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\BaseSigner::modifyHeader
     */
    public function modifyHeaderShouldChangeAlgorithmAndType()
    {
        $headers = [];

        $this->signer->modifyHeader($headers);

        $this->assertEquals($headers['typ'], 'JWS');
        $this->assertEquals($headers['alg'], 'TEST123');
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signature::__construct
     *
     * @covers Lcobucci\JWT\Signer\BaseSigner::sign
     */
    public function signMustReturnANewSignature()
    {
        $this->assertEquals(
            new Signature($this->signer, 'test'),
            $this->signer->sign('test', '123')
        );
    }
}
