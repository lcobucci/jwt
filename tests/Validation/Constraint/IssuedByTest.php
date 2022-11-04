<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy
 * @covers \Lcobucci\JWT\Validation\ConstraintViolation
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class IssuedByTest extends ConstraintTestCase
{
    /** @test */
    public function assertShouldRaiseExceptionWhenIssuerIsNotSet(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        $constraint = new IssuedBy('test.com', 'test.net');
        $constraint->assert($this->buildToken());
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenIssuerValueDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        $constraint = new IssuedBy('test.com', 'test.net');
        $constraint->assert($this->buildToken([RegisteredClaims::ISSUER => 'example.com']));
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenIssuerTypeValueDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        $constraint = new IssuedBy('test.com', '123');
        $constraint->assert($this->buildToken([RegisteredClaims::ISSUER => 123]));
    }

    /** @test */
    public function assertShouldNotRaiseExceptionWhenIssuerMatches(): void
    {
        $token      = $this->buildToken([RegisteredClaims::ISSUER => 'test.com']);
        $constraint = new IssuedBy('test.com', 'test.net');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
