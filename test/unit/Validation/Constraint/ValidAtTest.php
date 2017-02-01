<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeImmutable;
use Lcobucci\JWT\Token\RegisteredClaims;

final class ValidAtTest extends ConstraintTestCase
{
    /**
     * @var DateTimeImmutable
     */
    private $now;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->now = new DateTimeImmutable();
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
     */
    public function assertShouldRaiseExceptionWhenTokenIsExpired(): void
    {
        $currentTime = $this->now->getTimestamp();

        $claims = [
            RegisteredClaims::ISSUED_AT => $currentTime - 20,
            RegisteredClaims::NOT_BEFORE => $currentTime - 10,
            RegisteredClaims::EXPIRATION_TIME => $currentTime - 10,
        ];

        $constraint = new ValidAt($this->now);
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
     */
    public function assertShouldRaiseExceptionWhenMinimumTimeIsNotMet(): void
    {
        $currentTime = $this->now->getTimestamp();

        $claims = [
            RegisteredClaims::ISSUED_AT => $currentTime - 20,
            RegisteredClaims::NOT_BEFORE => $currentTime + 40,
            RegisteredClaims::EXPIRATION_TIME => $currentTime + 60,
        ];

        $constraint = new ValidAt($this->now);
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
     */
    public function assertShouldRaiseExceptionWhenTokenWasIssuedInTheFuture(): void
    {
        $currentTime = $this->now->getTimestamp();

        $claims = [
            RegisteredClaims::ISSUED_AT => $currentTime + 20,
            RegisteredClaims::NOT_BEFORE => $currentTime + 40,
            RegisteredClaims::EXPIRATION_TIME => $currentTime + 60,
        ];

        $constraint = new ValidAt($this->now);
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
     */
    public function assertShouldNotRaiseExceptionWhenTokenIsUsedInTheRightMoment(): void
    {
        $currentTime = $this->now->getTimestamp();
        $constraint = new ValidAt($this->now);

        $token = $this->buildToken(
            [
                RegisteredClaims::ISSUED_AT => $currentTime - 40,
                RegisteredClaims::NOT_BEFORE => $currentTime - 20,
                RegisteredClaims::EXPIRATION_TIME => $currentTime + 60,
            ]
        );

        self::assertNull($constraint->assert($token));

        $token = $this->buildToken(
            [
                RegisteredClaims::ISSUED_AT => $currentTime,
                RegisteredClaims::NOT_BEFORE => $currentTime,
                RegisteredClaims::EXPIRATION_TIME => $currentTime + 60,
            ]
        );

        self::assertNull($constraint->assert($token));
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
     */
    public function assertShouldNotRaiseExceptionWhenTokenDoesNotHaveTimeClaims(): void
    {
        $token = $this->buildToken();
        $constraint = new ValidAt($this->now);
        self::assertNull($constraint->assert($token));
    }
}
