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
     * @covers \Lcobucci\JWT\Validation\InvalidToken::violations
     */
    public function fromViolationsShouldConfigureMessageAndViolationList(): void
    {
        $violation = new ConstraintViolation('testing');
        $exception = InvalidToken::fromViolations($violation);

        self::assertSame(
            "The token violates some mandatory constraints, details:\n- testing",
            $exception->getMessage()
        );

        self::assertSame([$violation], $exception->violations());
    }
}
