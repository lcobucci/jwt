<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor
 * @covers \Lcobucci\JWT\Validation\ConstraintViolation
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class PermittedForTest extends ConstraintTestCase
{
    /** @test */
    public function assertShouldRaiseExceptionWhenAudienceIsNotSet(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint = new PermittedFor('test.com');
        $constraint->assert($this->buildToken());
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenAudienceValueDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint = new PermittedFor('test.com');
        $constraint->assert($this->buildToken([RegisteredClaims::AUDIENCE => ['aa.com']]));
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenAudienceTypeDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint = new PermittedFor('123');
        $constraint->assert($this->buildToken([RegisteredClaims::AUDIENCE => [123]]));
    }

    /** @test */
    public function assertShouldNotRaiseExceptionWhenAudienceMatches(): void
    {
        $token      = $this->buildToken([RegisteredClaims::AUDIENCE => ['aa.com', 'test.com']]);
        $constraint = new PermittedFor('test.com');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
