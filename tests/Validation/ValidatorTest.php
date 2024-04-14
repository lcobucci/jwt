<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(Validator::class)]
#[PHPUnit\UsesClass(ConstraintViolation::class)]
#[PHPUnit\UsesClass(RequiredConstraintsViolated::class)]
final class ValidatorTest extends TestCase
{
    private Token&MockObject $token;

    #[PHPUnit\Before]
    public function createDependencies(): void
    {
        $this->token = $this->createMock(Token::class);
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenNoConstraintIsGiven(): void
    {
        $validator = new Validator();

        $this->expectException(NoConstraintsGiven::class);

        $validator->assert($this->token, ...[]);
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenAtLeastOneConstraintFails(): void
    {
        $failedConstraint     = $this->createMock(Constraint::class);
        $successfulConstraint = $this->createMock(Constraint::class);

        $failedConstraint->expects($this->once())
                         ->method('assert')
                         ->willThrowException(new ConstraintViolation());

        $successfulConstraint->expects($this->once())
                             ->method('assert');

        $validator = new Validator();

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $validator->assert(
            $this->token,
            $failedConstraint,
            $successfulConstraint,
        );
    }

    #[PHPUnit\Test]
    public function assertShouldNotRaiseExceptionWhenNoConstraintFails(): void
    {
        $constraint = $this->createMock(Constraint::class);
        $constraint->expects($this->once())->method('assert');

        $validator = new Validator();

        $validator->assert($this->token, $constraint);
        $this->addToAssertionCount(1);
    }

    #[PHPUnit\Test]
    public function validateShouldRaiseExceptionWhenNoConstraintIsGiven(): void
    {
        $validator = new Validator();

        $this->expectException(NoConstraintsGiven::class);

        $validator->validate($this->token);
    }

    #[PHPUnit\Test]
    public function validateShouldReturnFalseWhenAtLeastOneConstraintFails(): void
    {
        $failedConstraint     = $this->createMock(Constraint::class);
        $successfulConstraint = $this->createMock(Constraint::class);

        $failedConstraint->expects($this->once())
                         ->method('assert')
                         ->willThrowException(new ConstraintViolation());

        $successfulConstraint->expects($this->never())
                             ->method('assert');

        $validator = new Validator();

        self::assertFalse(
            $validator->validate(
                $this->token,
                $failedConstraint,
                $successfulConstraint,
            ),
        );
    }

    #[PHPUnit\Test]
    public function validateShouldReturnTrueWhenNoConstraintFails(): void
    {
        $constraint = $this->createMock(Constraint::class);
        $constraint->expects($this->once())->method('assert');

        $validator = new Validator();
        self::assertTrue($validator->validate($this->token, $constraint));
    }
}
