<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

abstract class ValidAtTestCase extends ConstraintTestCase
{
    protected Clock $clock;

    /** @before */
    final public function createDependencies(): void
    {
        $this->clock = new FrozenClock(new DateTimeImmutable());
    }

    abstract protected function buildValidAtConstraint(Clock $clock, ?DateInterval $leeway = null): Constraint;

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::guardLeeway
     * @covers \Lcobucci\JWT\Validation\Constraint\LeewayCannotBeNegative
     */
    final public function constructShouldRaiseExceptionOnNegativeLeeway(): void
    {
        $leeway         = new DateInterval('PT30S');
        $leeway->invert = 1;

        $this->expectException(LeewayCannotBeNegative::class);
        $this->expectExceptionMessage('Leeway cannot be negative');

        $this->buildValidAtConstraint($this->clock, $leeway);
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
     * @covers \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    final public function assertShouldRaiseExceptionWhenTokenIsExpired(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('-10 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('-10 seconds'),
        ];

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is expired');

        $constraint = $this->buildValidAtConstraint($this->clock);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::guardLeeway
     * @covers ::assert
     * @covers ::assertIssueTime
     * @covers ::assertMinimumTime
     * @covers \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    final public function assertShouldRaiseExceptionWhenMinimumTimeIsNotMet(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
        ];

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token cannot be used yet');

        $constraint = $this->buildValidAtConstraint($this->clock);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::guardLeeway
     * @covers ::assert
     * @covers ::assertIssueTime
     * @covers \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    final public function assertShouldRaiseExceptionWhenTokenWasIssuedInTheFuture(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('+20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
        ];

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was issued in the future');

        $constraint = $this->buildValidAtConstraint($this->clock);
        $constraint->assert($this->buildToken($claims));
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
    final public function assertShouldNotRaiseExceptionWhenTokenIsUsedInTheRightMoment(): void
    {
        $constraint = $this->buildValidAtConstraint($this->clock);
        $now        = $this->clock->now();

        $token = $this->buildToken(
            [
                RegisteredClaims::ISSUED_AT => $now->modify('-40 seconds'),
                RegisteredClaims::NOT_BEFORE => $now->modify('-20 seconds'),
                RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
            ]
        );

        $constraint->assert($token);
        $this->addToAssertionCount(1);

        $token = $this->buildToken(
            [
                RegisteredClaims::ISSUED_AT => $now,
                RegisteredClaims::NOT_BEFORE => $now,
                RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
            ]
        );

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
