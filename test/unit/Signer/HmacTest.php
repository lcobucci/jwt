<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

use function hash_hmac;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Hmac */
final class HmacTest extends TestCase
{
    /** @var Hmac&MockObject */
    protected Hmac $signer;

    /** @before */
    public function initializeDependencies(): void
    {
        $this->signer = $this->getMockForAbstractClass(Hmac::class);

        $this->signer->expects(self::any())
                     ->method('algorithmId')
                     ->willReturn('TEST123');

        $this->signer->expects(self::any())
                     ->method('algorithm')
                     ->willReturn('sha256');
    }

    /**
     * @test
     *
     * @covers ::sign
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signMustReturnAHashAccordingWithTheAlgorithm(): string
    {
        $hash = hash_hmac('sha256', 'test', '123', true);

        self::assertEquals($hash, $this->signer->sign('test', InMemory::plainText('123')));

        return $hash;
    }

    /**
     * @test
     * @depends signMustReturnAHashAccordingWithTheAlgorithm
     *
     * @covers ::verify
     *
     * @uses \Lcobucci\JWT\Signer\Hmac::sign
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldReturnTrueWhenExpectedHashWasCreatedWithSameInformation(string $expected): void
    {
        self::assertTrue($this->signer->verify($expected, 'test', InMemory::plainText('123')));
    }

    /**
     * @test
     * @depends signMustReturnAHashAccordingWithTheAlgorithm
     *
     * @covers ::verify
     *
     * @uses \Lcobucci\JWT\Signer\Hmac::sign
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldReturnFalseWhenExpectedHashWasNotCreatedWithSameInformation(string $expected): void
    {
        self::assertFalse($this->signer->verify($expected, 'test', InMemory::plainText('1234')));
    }
}
