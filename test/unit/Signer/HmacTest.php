<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class HmacTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Hmac|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $signer;

    /**
     * @before
     */
    public function initializeDependencies()
    {
        $this->signer = $this->getMockForAbstractClass(Hmac::class);

        $this->signer->expects($this->any())
                     ->method('getAlgorithmId')
                     ->willReturn('TEST123');

        $this->signer->expects($this->any())
                     ->method('getAlgorithm')
                     ->willReturn('sha256');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Hmac::sign
     */
    public function signMustReturnAHashAccordingWithTheAlgorithm(): string
    {
        $hash = hash_hmac('sha256', 'test', '123', true);

        self::assertEquals($hash, $this->signer->sign('test', new Key('123')));

        return $hash;
    }

    /**
     * @test
     *
     * @depends signMustReturnAHashAccordingWithTheAlgorithm
     *
     * @uses \Lcobucci\JWT\Signer\Hmac::sign
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Hmac::verify
     */
    public function verifyShouldReturnTrueWhenExpectedHashWasCreatedWithSameInformation(string $expected)
    {
        self::assertTrue($this->signer->verify($expected, 'test', new Key('123')));
    }

    /**
     * @test
     *
     * @depends signMustReturnAHashAccordingWithTheAlgorithm
     *
     * @uses \Lcobucci\JWT\Signer\Hmac::sign
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Hmac::verify
     */
    public function verifyShouldReturnFalseWhenExpectedHashWasNotCreatedWithSameInformation($expected)
    {
        self::assertFalse($this->signer->verify($expected, 'test', new Key('1234')));
    }
}
