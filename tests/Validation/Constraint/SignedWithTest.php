<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
 * @covers \Lcobucci\JWT\Validation\ConstraintViolation
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class SignedWithTest extends ConstraintTestCase
{
    /** @var Signer&MockObject */
    private Signer $signer;
    private Signer\Key $key;
    /** @var Signer\Key[] */
    private array $keys;
    private Signature $signature;

    /** @before */
    public function createDependencies(): void
    {
        $this->signer = $this->createMock(Signer::class);
        $this->signer->method('algorithmId')->willReturn('RS256');

        $this->key       = Signer\Key\InMemory::plainText('123');
        $this->keys      = [
            Signer\Key\InMemory::plainText('abc'),
            Signer\Key\InMemory::plainText('123'),
        ];
        $this->signature = new Signature('1234', '5678');
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($this->createMock(Token::class));
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenSignerIsNotTheSame(): void
    {
        $token = $this->buildToken([], ['alg' => 'test'], $this->signature);

        $this->signer->expects(self::never())->method('verify');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signer mismatch');

        $constraint = new SignedWith($this->signer, $this->key);
        $constraint->assert($token);
    }

    /** @test */
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

    /** @test */
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

    /** @test */
    public function assertShouldNotRaiseExceptionWhenSignatureIsValidWithMultipleKeys(): void
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);
        $this->signer->expects(self::exactly(2))
            ->method('verify')
            ->willReturnCallback(fn (string $expected, string $payload, Key $key) => $key->contents() === '123');

        $constraint = new SignedWith($this->signer, $this->keys);
        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenSignatureIsInValidWithMultipleKeys(): void
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);
        $this->signer->expects(self::exactly(2))
            ->method('verify')
            ->willReturn(false);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signature mismatch');

        $constraint = new SignedWith($this->signer, $this->keys);
        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
