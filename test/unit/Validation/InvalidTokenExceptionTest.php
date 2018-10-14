<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use PHPUnit\Framework\TestCase;

final class InvalidTokenExceptionTest extends TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\InvalidToken::fromViolations
     * @covers \Lcobucci\JWT\Validation\InvalidToken::buildMessage
     */
    public function fromViolationsShouldConfigureMessageAndViolationList(): void
    {
        $violation = new ConstraintViolation('testing');
        $exception = InvalidToken::fromViolations($violation);

        self::assertAttributeEquals(
            "The token violates some mandatory constraints, details:\n- testing",
            'message',
            $exception
        );

        self::assertAttributeSame([$violation], 'violations', $exception);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\InvalidToken::violations
     *
     * @uses \Lcobucci\JWT\Validation\InvalidToken::fromViolations
     * @uses \Lcobucci\JWT\Validation\InvalidToken::buildMessage
     */
    public function violationsShouldReturnTheViolationList(): void
    {
        $violation = new ConstraintViolation('testing');
        $exception = InvalidToken::fromViolations($violation);

        self::assertSame([$violation], $exception->violations());
    }
}
