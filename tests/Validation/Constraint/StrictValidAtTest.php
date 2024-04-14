<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use DateInterval;
use Lcobucci\Clock\Clock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(Constraint\LeewayCannotBeNegative::class)]
#[PHPUnit\CoversClass(StrictValidAt::class)]
#[PHPUnit\UsesClass(Token\DataSet::class)]
#[PHPUnit\UsesClass(Token\Plain::class)]
#[PHPUnit\UsesClass(Token\Signature::class)]
final class StrictValidAtTest extends ValidAtTestCase
{
    protected function buildValidAtConstraint(Clock $clock, ?DateInterval $leeway = null): Constraint
    {
        return new StrictValidAt($clock, $leeway);
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $constraint = $this->buildValidAtConstraint($this->clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint->assert($this->createMock(Token::class));
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenIatClaimIsMissing(): void
    {
        $constraint = $this->buildValidAtConstraint($this->clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('"Issued At" claim missing');

        $constraint->assert($this->buildToken());
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenNbfClaimIsMissing(): void
    {
        $now    = $this->clock->now();
        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-5 seconds'),
        ];

        $constraint = $this->buildValidAtConstraint($this->clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('"Not Before" claim missing');

        $constraint->assert($this->buildToken($claims));
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
        $this->expectExceptionMessage('"Expiration Time" claim missing');

        $constraint->assert($this->buildToken($claims));
    }
}
