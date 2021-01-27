<?php

namespace Lcobucci\JWT\Validation\Constraint;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\ValidAt
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token
 * @uses \Lcobucci\JWT\Signature
 * @uses \Lcobucci\JWT\Claim\Factory
 */
final class ValidAtTest extends ConstraintTestCase
{
    /** @var Clock */
    private $clock;

    /** @before */
    public function createDependencies()
    {
        $this->clock = new FrozenClock(new DateTimeImmutable());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::guardLeeway
     * @covers \Lcobucci\JWT\Validation\Constraint\LeewayCannotBeNegative
     */
    public function constructShouldRaiseExceptionOnNegativeLeeway()
    {
        $leeway         = new DateInterval('PT30S');
        $leeway->invert = 1;

        $this->expectException(LeewayCannotBeNegative::class);
        $this->expectExceptionMessage('Leeway cannot be negative');

        new ValidAt($this->clock, $leeway);
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
     */
    public function assertShouldRaiseExceptionWhenTokenIsExpired()
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('-10 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('-10 seconds'),
        ];

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is expired');

        $constraint = new ValidAt($this->clock);
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
     */
    public function assertShouldRaiseExceptionWhenMinimumTimeIsNotMet()
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
        ];

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token cannot be used yet');

        $constraint = new ValidAt($this->clock);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::guardLeeway
     * @covers ::assert
     * @covers ::assertIssueTime
     */
    public function assertShouldRaiseExceptionWhenTokenWasIssuedInTheFuture()
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('+20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
        ];

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was issued in the future');

        $constraint = new ValidAt($this->clock);
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
     */
    public function assertShouldNotRaiseExceptionWhenLeewayIsUsed()
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('+5 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+5 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('-5 seconds'),
        ];

        $constraint = new ValidAt($this->clock, new DateInterval('PT6S'));
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
     */
    public function assertShouldNotRaiseExceptionWhenTokenIsUsedInTheRightMoment()
    {
        $constraint = new ValidAt($this->clock);
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

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::guardLeeway
     * @covers ::assert
     * @covers ::assertExpiration
     * @covers ::assertIssueTime
     * @covers ::assertMinimumTime
     */
    public function assertShouldNotRaiseExceptionWhenTokenDoesNotHaveTimeClaims()
    {
        $token      = $this->buildToken();
        $constraint = new ValidAt($this->clock);

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
