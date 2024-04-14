<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(RelatedTo::class)]
#[PHPUnit\UsesClass(Token\DataSet::class)]
#[PHPUnit\UsesClass(Token\Plain::class)]
#[PHPUnit\UsesClass(Token\Signature::class)]
final class RelatedToTest extends ConstraintTestCase
{
    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenSubjectIsNotSet(): void
    {
        $constraint = new RelatedTo('user-auth');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not related to the expected subject');

        $constraint->assert($this->buildToken());
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenSubjectDoesNotMatch(): void
    {
        $constraint = new RelatedTo('user-auth');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not related to the expected subject');

        $constraint->assert($this->buildToken([RegisteredClaims::SUBJECT => 'password-recovery']));
    }

    #[PHPUnit\Test]
    public function assertShouldNotRaiseExceptionWhenSubjectMatches(): void
    {
        $token      = $this->buildToken([RegisteredClaims::SUBJECT => 'user-auth']);
        $constraint = new RelatedTo('user-auth');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
