<?php

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit_Framework_MockObject_MockObject;

/**
 * @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\SignedWith
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token
 * @uses \Lcobucci\JWT\Signature
 * @uses \Lcobucci\JWT\Signer\Key
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 * @uses \Lcobucci\JWT\Claim\Factory
 */
final class SignedWithTest extends ConstraintTestCase
{
    /** @var Signer&PHPUnit_Framework_MockObject_MockObject */
    private $signer;

    /** @var Signer\Key */
    private $key;

    /** @var Signature */
    private $signature;

    /** @before */
    public function createDependencies()
    {
        $this->signer = $this->createMock(Signer::class);
        $this->signer->method('getAlgorithmId')->willReturn('RS256');

        $this->key       = Signer\Key\InMemory::plainText('123');
        $this->signature = new Signature('1234');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenSignerIsNotTheSame()
    {
        $token = $this->buildToken([], ['alg' => 'test'], $this->signature);

        $this->signer->expects(self::never())->method('verify');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signer mismatch');

        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($token);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenSignatureIsInvalid()
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);

        $this->signer->expects(self::once())
                     ->method('verify')
                     ->with((string) $this->signature, $token->getPayload(), $this->key)
                     ->willReturn(false);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signature mismatch');

        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($token);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenSignatureIsValid()
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);

        $this->signer->expects(self::once())
                     ->method('verify')
                     ->with((string) $this->signature, $token->getPayload(), $this->key)
                     ->willReturn(true);

        $constraint = new SignedWith($this->signer, $this->key);

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
