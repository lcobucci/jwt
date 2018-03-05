<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;
use PHPUnit\Framework\TestCase;

final class ValidatorTest extends TestCase
{
    /**
     * @var Token|\PHPUnit_Framework_MockObject_MockObject
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
     * @expectedException \Lcobucci\JWT\Validation\InvalidTokenException
     *
     * @covers \Lcobucci\JWT\Validation\Validator::assert
     * @covers \Lcobucci\JWT\Validation\Validator::checkConstraint
     *
     * @uses \Lcobucci\JWT\Validation\InvalidTokenException
     */
    public function assertShouldRaiseExceptionWhenAtLeastOneConstraintFails(): void
    {
        $failedConstraint     = $this->createMock(Constraint::class);
        $successfulConstraint = $this->createMock(Constraint::class);

        $failedConstraint->expects($this->once())
                         ->method('assert')
                         ->willThrowException(new ConstraintViolationException());

        $successfulConstraint->expects($this->once())
                             ->method('assert');

        $validator = new Validator();

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
        $constraint->expects($this->once())->method('assert');

        $validator = new Validator();

        $validator->assert($this->token, $constraint);
        $this->addToAssertionCount(1);
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

        $failedConstraint->expects($this->once())
                         ->method('assert')
                         ->willThrowException(new ConstraintViolationException());

        $successfulConstraint->expects($this->never())
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
        $constraint->expects($this->once())->method('assert');

        $validator = new Validator();
        self::assertTrue($validator->validate($this->token, $constraint));
    }
}
