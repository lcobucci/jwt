<?php

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Lcobucci\JWT\Signer\None
 *
 * @covers \Lcobucci\JWT\Signer\BaseSigner
 *
 * @uses \Lcobucci\JWT\Signature
 * @uses \Lcobucci\JWT\Signer\Key
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 */
final class NoneTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::getAlgorithmId
     */
    public function algorithmIdMustBeCorrect()
    {
        $signer = new None();

        self::assertEquals('none', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers ::createHash
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldReturnAnEmptyString()
    {
        $signer = new None();

        self::assertEquals('', $signer->sign('test', InMemory::plainText('test')));
    }

    /**
     * @test
     *
     * @covers ::doVerify
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldReturnTrueWhenSignatureHashIsEmpty()
    {
        $signer = new None();

        self::assertTrue($signer->verify('', 'test', InMemory::plainText('test')));
    }

    /**
     * @test
     *
     * @covers ::doVerify
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldReturnFalseWhenSignatureHashIsEmpty()
    {
        $signer = new None();

        self::assertFalse($signer->verify('testing', 'test', InMemory::plainText('test')));
    }
}
