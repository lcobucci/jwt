<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

/**
 * @author Luís Cobucci <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class NoneTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\None::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect(): void
    {
        $signer = new None();

        self::assertEquals('none', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\None::sign
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function signShouldReturnAnEmptyString(): void
    {
        $signer = new None();

        self::assertEquals('', $signer->sign('test', new Key('test')));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\None::verify
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function verifyShouldReturnTrueWhenSignatureHashIsEmpty(): void
    {
        $signer = new None();

        self::assertTrue($signer->verify('', 'test', new Key('test')));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\None::verify
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function verifyShouldReturnFalseWhenSignatureHashIsEmpty(): void
    {
        $signer = new None();

        self::assertFalse($signer->verify('testing', 'test', new Key('test')));
    }
}
