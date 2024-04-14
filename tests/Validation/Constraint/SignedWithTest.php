<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\MockObject\MockObject;

#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(SignedWith::class)]
#[PHPUnit\UsesClass(Signer\Key\InMemory::class)]
#[PHPUnit\UsesClass(Token\DataSet::class)]
#[PHPUnit\UsesClass(Token\Plain::class)]
#[PHPUnit\UsesClass(Token\Signature::class)]
final class SignedWithTest extends ConstraintTestCase
{
    private Signer&MockObject $signer;
    private Signer\Key $key;
    private Signature $signature;

    #[PHPUnit\Before]
    public function createDependencies(): void
    {
        $this->signer = $this->createMock(Signer::class);
        $this->signer->method('algorithmId')->willReturn('RS256');

        $this->key       = Signer\Key\InMemory::plainText('123');
        $this->signature = new Signature('1234', '5678');
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $constraint = new SignedWith($this->signer, $this->key);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint->assert($this->createMock(Token::class));
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenSignerIsNotTheSame(): void
    {
        $token = $this->buildToken([], ['alg' => 'test'], $this->signature);

        $this->signer->expects($this->never())->method('verify');

        $constraint = new SignedWith($this->signer, $this->key);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signer mismatch');

        $constraint->assert($token);
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenSignatureIsInvalid(): void
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);

        $this->signer->expects($this->once())
                     ->method('verify')
                     ->with($this->signature->hash(), $token->payload(), $this->key)
                     ->willReturn(false);

        $constraint = new SignedWith($this->signer, $this->key);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signature mismatch');

        $constraint->assert($token);
    }

    #[PHPUnit\Test]
    public function assertShouldNotRaiseExceptionWhenSignatureIsValid(): void
    {
        $token = $this->buildToken([], ['alg' => 'RS256'], $this->signature);

        $this->signer->expects($this->once())
                     ->method('verify')
                     ->with($this->signature->hash(), $token->payload(), $this->key)
                     ->willReturn(true);

        $constraint = new SignedWith($this->signer, $this->key);

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
