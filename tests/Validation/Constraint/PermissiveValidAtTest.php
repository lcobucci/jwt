<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use DateInterval;
use Lcobucci\Clock\Clock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\PermissiveValidAt;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(Constraint\LeewayCannotBeNegative::class)]
#[PHPUnit\CoversClass(PermissiveValidAt::class)]
#[PHPUnit\UsesClass(Token\DataSet::class)]
#[PHPUnit\UsesClass(Token\Plain::class)]
#[PHPUnit\UsesClass(Token\Signature::class)]
final class PermissiveValidAtTest extends ValidAtTestCase
{
    protected function buildValidAtConstraint(Clock $clock, ?DateInterval $leeway = null): Constraint
    {
        return new PermissiveValidAt($clock, $leeway);
    }

    #[PHPUnit\Test]
    public function assertShouldNotRaiseExceptionWhenOnlyExperationTimeIsProvided(): void
    {
        $claims     = [
            RegisteredClaims::EXPIRATION_TIME => $this->clock->now()->modify('5 minutes'),
        ];
        $token      = $this->buildToken($claims);
        $constraint = $this->buildValidAtConstraint($this->clock);

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenExpClaimIsMissing(): void
    {
        $now    = $this->clock->now();
        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-5 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('-5 seconds'),
        ];

        $constraint = $this->buildValidAtConstraint($this->clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageIs('"Expiration Time" claim missing');

        $constraint->assert($this->buildToken($claims));
    }
}
