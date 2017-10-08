<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

final class InvalidTokenExceptionTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException::fromViolations
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException::buildMessage
     */
    public function fromViolationsShouldConfigureMessageAndViolationList(): void
    {
        $violation = new ConstraintViolationException('testing');
        $exception = InvalidTokenException::fromViolations($violation);

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
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException::violations
     *
     * @uses \Lcobucci\JWT\Validation\InvalidTokenException::fromViolations
     * @uses \Lcobucci\JWT\Validation\InvalidTokenException::buildMessage
     */
    public function violationsShouldReturnTheViolationList(): void
    {
        $violation = new ConstraintViolationException('testing');
        $exception = InvalidTokenException::fromViolations($violation);

        self::assertSame([$violation], $exception->violations());
    }
}
