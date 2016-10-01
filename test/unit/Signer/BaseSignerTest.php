<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

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
     * @before
     */
    public function initializeDependencies()
    {
        $this->signer = $this->getMockForAbstractClass(BaseSigner::class);

        $this->signer->method('getAlgorithmId')
                     ->willReturn('TEST123');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\BaseSigner::modifyHeader
     */
    public function modifyHeaderShouldChangeAlgorithm()
    {
        $headers = $this->signer->modifyHeader(['typ' => 'JWT']);

        self::assertEquals($headers['typ'], 'JWT');
        self::assertEquals($headers['alg'], 'TEST123');
    }
}
