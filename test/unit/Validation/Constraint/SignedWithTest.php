<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\MockObject\MockObject;

final class SignedWithTest extends ConstraintTestCase
{
    /**
     * @var Signer|MockObject
     */
    private $signer;

    /**
     * @var Signer\Key
     */
    private $key;

    /**
     * @var Signature
     */
    private $signature;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->signer = $this->createMock(Signer::class);
        $this->signer->method('getAlgorithmId')->willReturn('RS256');

        $this->key       = new Signer\Key('123');
        $this->signature = new Signature('1234', '5678');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($this->createMock(Token::class));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenSignerIsNotTheSame(): void
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
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenSignatureIsInvalid(): void
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);

        $this->signer->expects(self::once())
                     ->method('verify')
                     ->with($this->signature->hash(), $token->payload(), $this->key)
                     ->willReturn(false);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signature mismatch');

        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($token);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenSignatureIsValid(): void
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);

        $this->signer->expects(self::once())
                     ->method('verify')
                     ->with($this->signature->hash(), $token->payload(), $this->key)
                     ->willReturn(true);

        $constraint = new SignedWith($this->signer, $this->key);

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
