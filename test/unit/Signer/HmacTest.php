<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use function hash_hmac;

final class HmacTest extends TestCase
{
    /**
     * @var Hmac|MockObject
     */
    protected $signer;

    /**
     * @before
     */
    public function initializeDependencies(): void
    {
        $this->signer = $this->getMockForAbstractClass(Hmac::class);

        $this->signer->expects(self::any())
                     ->method('getAlgorithmId')
                     ->willReturn('TEST123');

        $this->signer->expects(self::any())
                     ->method('getAlgorithm')
                     ->willReturn('sha256');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Hmac::sign
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function signMustReturnAHashAccordingWithTheAlgorithm(): string
    {
        $hash = \hash_hmac('sha256', 'test', '123', true);

        self::assertEquals($hash, $this->signer->sign('test', new Key('123')));

        return $hash;
    }

    /**
     * @test
     * @depends signMustReturnAHashAccordingWithTheAlgorithm
     *
     * @covers \Lcobucci\JWT\Signer\Hmac::verify
     *
     * @uses \Lcobucci\JWT\Signer\Hmac::sign
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function verifyShouldReturnTrueWhenExpectedHashWasCreatedWithSameInformation(string $expected): void
    {
        self::assertTrue($this->signer->verify($expected, 'test', new Key('123')));
    }

    /**
     * @test
     * @depends signMustReturnAHashAccordingWithTheAlgorithm
     *
     * @covers \Lcobucci\JWT\Signer\Hmac::verify
     *
     * @uses \Lcobucci\JWT\Signer\Hmac::sign
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function verifyShouldReturnFalseWhenExpectedHashWasNotCreatedWithSameInformation(string $expected): void
    {
        self::assertFalse($this->signer->verify($expected, 'test', new Key('1234')));
    }
}
