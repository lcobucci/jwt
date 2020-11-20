<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\MockObject\MockObject;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\SignedWith */
final class SignedWithTest extends ConstraintTestCase
{
    /** @var Signer&MockObject */
    private Signer $signer;
    private Signer\Key $key;
    private Signature $signature;

    /** @before */
    public function createDependencies(): void
    {
        $this->signer = $this->createMock(Signer::class);
        $this->signer->method('algorithmId')->willReturn('RS256');

        $this->key       = Signer\Key\InMemory::plainText('123');
        $this->signature = new Signature('1234', '5678');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
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
     * @covers ::__construct
     * @covers ::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
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
     * @covers ::__construct
     * @covers ::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
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
     * @covers ::__construct
     * @covers ::assert
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
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
