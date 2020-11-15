<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Validation\RequiredConstraintsViolated */
final class RequiredConstraintsViolatedTest extends TestCase
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
        $exception = RequiredConstraintsViolated::fromViolations($violation);

        self::assertSame(
            "The token violates some mandatory constraints, details:\n- testing",
            $exception->getMessage()
        );

        self::assertSame([$violation], $exception->violations());
    }
}
