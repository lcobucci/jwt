<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Validator */
final class ValidatorTest extends TestCase
{
    /** @var Token&MockObject */
    private Token $token;

    /** @before */
    public function createDependencies(): void
    {
        $this->token = $this->createMock(Token::class);
    }

    /**
     * @test
     *
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenNoConstraintIsGiven(): void
    {
        $validator = new Validator();

        $this->expectException(NoConstraintsGiven::class);

        $validator->assert($this->token, ...[]);
    }

    /**
     * @test
     *
     * @covers ::assert
     * @covers ::checkConstraint
     *
     * @uses \Lcobucci\JWT\Validation\RequiredConstraintsViolated
     */
    public function assertShouldRaiseExceptionWhenAtLeastOneConstraintFails(): void
    {
        $failedConstraint     = $this->createMock(Constraint::class);
        $successfulConstraint = $this->createMock(Constraint::class);

        $failedConstraint->expects(self::once())
                         ->method('assert')
                         ->willThrowException(new ConstraintViolation());

        $successfulConstraint->expects(self::once())
                             ->method('assert');

        $validator = new Validator();

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $validator->assert(
            $this->token,
            $failedConstraint,
            $successfulConstraint
        );
    }

    /**
     * @test
     *
     * @covers ::assert
     * @covers ::checkConstraint
     */
    public function assertShouldNotRaiseExceptionWhenNoConstraintFails(): void
    {
        $constraint = $this->createMock(Constraint::class);
        $constraint->expects(self::once())->method('assert');

        $validator = new Validator();

        $validator->assert($this->token, $constraint);
        $this->addToAssertionCount(1);
    }

    /**
     * @test
     *
     * @covers ::validate
     */
    public function validateShouldRaiseExceptionWhenNoConstraintIsGiven(): void
    {
        $validator = new Validator();

        $this->expectException(NoConstraintsGiven::class);

        $validator->validate($this->token, ...[]);
    }

    /**
     * @test
     *
     * @covers ::validate
     */
    public function validateShouldReturnFalseWhenAtLeastOneConstraintFails(): void
    {
        $failedConstraint     = $this->createMock(Constraint::class);
        $successfulConstraint = $this->createMock(Constraint::class);

        $failedConstraint->expects(self::once())
                         ->method('assert')
                         ->willThrowException(new ConstraintViolation());

        $successfulConstraint->expects(self::never())
                             ->method('assert');

        $validator = new Validator();

        self::assertFalse(
            $validator->validate(
                $this->token,
                $failedConstraint,
                $successfulConstraint
            )
        );
    }

    /**
     * @test
     *
     * @covers ::validate
     */
    public function validateShouldReturnTrueWhenNoConstraintFails(): void
    {
        $constraint = $this->createMock(Constraint::class);
        $constraint->expects(self::once())->method('assert');

        $validator = new Validator();
        self::assertTrue($validator->validate($this->token, $constraint));
    }
}
