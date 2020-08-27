<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Validation\InvalidToken */
final class InvalidTokenExceptionTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::fromViolations
     * @covers ::buildMessage
     * @covers ::violations
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
