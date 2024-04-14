<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation;

use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(RequiredConstraintsViolated::class)]
#[PHPUnit\UsesClass(ConstraintViolation::class)]
final class RequiredConstraintsViolatedTest extends TestCase
{
    #[PHPUnit\Test]
    public function fromViolationsShouldConfigureMessageAndViolationList(): void
    {
        $violation = new ConstraintViolation('testing');
        $exception = RequiredConstraintsViolated::fromViolations($violation);

        self::assertSame(
            "The token violates some mandatory constraints, details:\n- testing",
            $exception->getMessage(),
        );

        self::assertSame([$violation], $exception->violations());
    }
}
