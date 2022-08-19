<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use DateInterval;
use Lcobucci\Clock\Clock;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\LooseValidAt */
final class LooseValidAtTest extends ValidAtTestCase
{
    protected function buildValidAtConstraint(Clock $clock, ?DateInterval $leeway = null): Constraint
    {
        return new LooseValidAt($clock, $leeway);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::guardLeeway
     * @covers ::assert
     * @covers ::assertExpiration
     * @covers ::assertIssueTime
     * @covers ::assertMinimumTime
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenTokenDoesNotHaveTimeClaims(): void
    {
        $token      = $this->buildToken();
        $constraint = $this->buildValidAtConstraint($this->clock);

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
