<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\LeewayCannotBeNegative;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;

abstract class ValidAtTestCase extends ConstraintTestCase
{
    protected Clock $clock;

    #[PHPUnit\Before]
    final public function createDependencies(): void
    {
        $this->clock = new FrozenClock(new DateTimeImmutable());
    }

    abstract protected function buildValidAtConstraint(Clock $clock, ?DateInterval $leeway = null): Constraint;

    #[PHPUnit\Test]
    final public function constructShouldRaiseExceptionOnNegativeLeeway(): void
    {
        $leeway         = new DateInterval('PT30S');
        $leeway->invert = 1;

        $this->expectException(LeewayCannotBeNegative::class);
        $this->expectExceptionMessage('Leeway cannot be negative');

        $this->buildValidAtConstraint($this->clock, $leeway);
    }

    #[PHPUnit\Test]
    final public function assertShouldRaiseExceptionWhenTokenIsExpired(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('-10 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('-10 seconds'),
        ];

        $constraint = $this->buildValidAtConstraint($this->clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is expired');

        $constraint->assert($this->buildToken($claims));
    }

    #[PHPUnit\Test]
    final public function assertShouldRaiseExceptionWhenMinimumTimeIsNotMet(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
        ];

        $constraint = $this->buildValidAtConstraint($this->clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token cannot be used yet');

        $constraint->assert($this->buildToken($claims));
    }

    #[PHPUnit\Test]
    final public function assertShouldRaiseExceptionWhenTokenWasIssuedInTheFuture(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('+20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
        ];

        $constraint = $this->buildValidAtConstraint($this->clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was issued in the future');

        $constraint->assert($this->buildToken($claims));
    }

    #[PHPUnit\Test]
    final public function assertShouldNotRaiseExceptionWhenLeewayIsUsed(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('+5 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+5 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('-5 seconds'),
        ];

        $constraint = $this->buildValidAtConstraint($this->clock, new DateInterval('PT6S'));
        $constraint->assert($this->buildToken($claims));

        $this->addToAssertionCount(1);
    }

    #[PHPUnit\Test]
    final public function assertShouldNotRaiseExceptionWhenTokenIsUsedInTheRightMoment(): void
    {
        $constraint = $this->buildValidAtConstraint($this->clock);
        $now        = $this->clock->now();

        $token = $this->buildToken(
            [
                RegisteredClaims::ISSUED_AT => $now->modify('-40 seconds'),
                RegisteredClaims::NOT_BEFORE => $now->modify('-20 seconds'),
                RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
            ],
        );

        $constraint->assert($token);
        $this->addToAssertionCount(1);

        $token = $this->buildToken(
            [
                RegisteredClaims::ISSUED_AT => $now,
                RegisteredClaims::NOT_BEFORE => $now,
                RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
            ],
        );

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
