<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ValidatorTest extends TestCase
{
    /**
     * @var Token|MockObject
     */
    private $token;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->token = $this->createMock(Token::class);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Validator::assert
     * @covers \Lcobucci\JWT\Validation\Validator::checkConstraint
     *
     * @uses \Lcobucci\JWT\Validation\InvalidToken
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

        $this->expectException(InvalidToken::class);
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
     * @covers \Lcobucci\JWT\Validation\Validator::assert
     * @covers \Lcobucci\JWT\Validation\Validator::checkConstraint
     */
    public function assertShouldNotRaiseExceptionWhenNoConstraintFails(): void
    {
        $constraint = $this->createMock(Constraint::class);
        $constraint->expects(self::once())->method('assert');

        $validator = new Validator();

        $validator->assert($this->token, $constraint);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Validator::validate
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
     * @covers \Lcobucci\JWT\Validation\Validator::validate
     */
    public function validateShouldReturnTrueWhenNoConstraintFails(): void
    {
        $constraint = $this->createMock(Constraint::class);
        $constraint->expects(self::once())->method('assert');

        $validator = new Validator();
        self::assertTrue($validator->validate($this->token, $constraint));
    }
}
