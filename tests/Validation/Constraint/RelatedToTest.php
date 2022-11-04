<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo
 * @covers \Lcobucci\JWT\Validation\ConstraintViolation
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class RelatedToTest extends ConstraintTestCase
{
    /** @test */
    public function assertShouldRaiseExceptionWhenSubjectIsNotSet(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not related to the expected subject');

        $constraint = new RelatedTo('user-auth');
        $constraint->assert($this->buildToken());
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenSubjectDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not related to the expected subject');

        $constraint = new RelatedTo('user-auth');
        $constraint->assert($this->buildToken([RegisteredClaims::SUBJECT => 'password-recovery']));
    }

    /** @test */
    public function assertShouldNotRaiseExceptionWhenSubjectMatches(): void
    {
        $token      = $this->buildToken([RegisteredClaims::SUBJECT => 'user-auth']);
        $constraint = new RelatedTo('user-auth');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
