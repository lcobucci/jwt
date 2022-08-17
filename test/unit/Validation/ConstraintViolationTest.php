<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Validation\ConstraintViolation */
final class ConstraintViolationTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::error
     * @covers ::constraint
     *
     * @uses \Lcobucci\JWT\Validation\Constraint\IdentifiedBy
     */
    public function errorShouldConfigureMessageAndConstraint(): void
    {
        $violation = ConstraintViolation::error('testing', new IdentifiedBy('token id'));

        self::assertSame('testing', $violation->getMessage());
        self::assertSame(IdentifiedBy::class, $violation->constraint);
    }
}
