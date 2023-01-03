<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use DateInterval;
use Lcobucci\Clock\Clock;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;

/**
 * @covers \Lcobucci\JWT\Validation\Constraint\LeewayCannotBeNegative
 * @covers \Lcobucci\JWT\Validation\ConstraintViolation
 * @covers \Lcobucci\JWT\Validation\Constraint\LooseValidAt
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class LooseValidAtTest extends ValidAtTestCase
{
    protected function buildValidAtConstraint(Clock $clock, ?DateInterval $leeway = null): Constraint
    {
        return new LooseValidAt($clock, $leeway);
    }

    /** @test */
    public function assertShouldNotRaiseExceptionWhenTokenDoesNotHaveTimeClaims(): void
    {
        $token      = $this->buildToken();
        $constraint = $this->buildValidAtConstraint($this->clock);

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
