<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation;

use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\UsesClass(IdentifiedBy::class)]
final class ConstraintViolationTest extends TestCase
{
    #[PHPUnit\Test]
    public function errorShouldConfigureMessageAndConstraint(): void
    {
        $violation = ConstraintViolation::error('testing', new IdentifiedBy('token id'));

        self::assertSame('testing', $violation->getMessage());
        self::assertSame(IdentifiedBy::class, $violation->constraint);
    }
}
