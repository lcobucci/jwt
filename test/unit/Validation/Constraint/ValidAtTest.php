<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeImmutable;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Token\RegisteredClaims;

final class ValidAtTest extends ConstraintTestCase
{
    /**
     * @var Clock
     */
    private $clock;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->clock = new FrozenClock(new DateTimeImmutable());
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertIssueTime
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertMinimumTime
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenTokenIsExpired(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('-10 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('-10 seconds'),
        ];

        $constraint = new ValidAt($this->clock);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertIssueTime
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertMinimumTime
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenMinimumTimeIsNotMet(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
        ];

        $constraint = new ValidAt($this->clock);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertIssueTime
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenTokenWasIssuedInTheFuture(): void
    {
        $now = $this->clock->now();

        $claims = [
            RegisteredClaims::ISSUED_AT => $now->modify('+20 seconds'),
            RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
        ];

        $constraint = new ValidAt($this->clock);
        $constraint->assert($this->buildToken($claims));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertIssueTime
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertMinimumTime
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenTokenIsUsedInTheRightMoment(): void
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
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assert
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertExpiration
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertIssueTime
     * @covers \Lcobucci\JWT\Validation\Constraint\ValidAt::assertMinimumTime
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenTokenDoesNotHaveTimeClaims(): void
    {
        $token      = $this->buildToken();
        $constraint = new ValidAt($this->clock);

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
