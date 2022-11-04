<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy
 * @covers \Lcobucci\JWT\Validation\ConstraintViolation
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class IdentifiedByTest extends ConstraintTestCase
{
    /** @test */
    public function assertShouldRaiseExceptionWhenIdIsNotSet(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not identified with the expected ID');

        $constraint = new IdentifiedBy('123456');
        $constraint->assert($this->buildToken());
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenIdDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not identified with the expected ID');

        $constraint = new IdentifiedBy('123456');
        $constraint->assert($this->buildToken([RegisteredClaims::ID => 15]));
    }

    /** @test */
    public function assertShouldNotRaiseExceptionWhenIdMatches(): void
    {
        $token = $this->buildToken([RegisteredClaims::ID => '123456']);

        $constraint = new IdentifiedBy('123456');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
