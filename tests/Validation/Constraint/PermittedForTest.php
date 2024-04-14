<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(PermittedFor::class)]
#[PHPUnit\UsesClass(Token\DataSet::class)]
#[PHPUnit\UsesClass(Token\Plain::class)]
#[PHPUnit\UsesClass(Token\Signature::class)]
final class PermittedForTest extends ConstraintTestCase
{
    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenAudienceIsNotSet(): void
    {
        $constraint = new PermittedFor('test.com');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint->assert($this->buildToken());
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenAudienceValueDoesNotMatch(): void
    {
        $constraint = new PermittedFor('test.com');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint->assert($this->buildToken([RegisteredClaims::AUDIENCE => ['aa.com']]));
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenAudienceTypeDoesNotMatch(): void
    {
        $constraint = new PermittedFor('123');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint->assert($this->buildToken([RegisteredClaims::AUDIENCE => [123]]));
    }

    #[PHPUnit\Test]
    public function assertShouldNotRaiseExceptionWhenAudienceMatches(): void
    {
        $token      = $this->buildToken([RegisteredClaims::AUDIENCE => ['aa.com', 'test.com']]);
        $constraint = new PermittedFor('test.com');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
