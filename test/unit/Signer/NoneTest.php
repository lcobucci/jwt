<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\None */
final class NoneTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::algorithmId
     */
    public function algorithmIdMustBeCorrect(): void
    {
        $signer = new None();

        self::assertEquals('none', $signer->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::sign
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldReturnAnEmptyString(): void
    {
        $signer = new None();

        self::assertEquals('', $signer->sign('test', InMemory::plainText('test')));
    }

    /**
     * @test
     *
     * @covers ::verify
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldReturnTrueWhenSignatureHashIsEmpty(): void
    {
        $signer = new None();

        self::assertTrue($signer->verify('', 'test', InMemory::plainText('test')));
    }

    /**
     * @test
     *
     * @covers ::verify
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldReturnFalseWhenSignatureHashIsEmpty(): void
    {
        $signer = new None();

        self::assertFalse($signer->verify('testing', 'test', InMemory::plainText('test')));
    }
}
