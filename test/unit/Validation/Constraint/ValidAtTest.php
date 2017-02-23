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
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenTokenIsExpired(): void
    {
        $claims = [
            RegisteredClaims::ISSUED_AT => $this->now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $this->now->modify('-10 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $this->now->modify('-10 seconds'),
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
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenMinimumTimeIsNotMet(): void
    {
        $claims = [
            RegisteredClaims::ISSUED_AT => $this->now->modify('-20 seconds'),
            RegisteredClaims::NOT_BEFORE => $this->now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $this->now->modify('+60 seconds'),
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
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenTokenWasIssuedInTheFuture(): void
    {
        $claims = [
            RegisteredClaims::ISSUED_AT => $this->now->modify('+20 seconds'),
            RegisteredClaims::NOT_BEFORE => $this->now->modify('+40 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $this->now->modify('+60 seconds'),
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
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenTokenIsUsedInTheRightMoment(): void
    {
        $constraint = new ValidAt($this->now);

        $token = $this->buildToken(
            [
                RegisteredClaims::ISSUED_AT => $this->now->modify('-40 seconds'),
                RegisteredClaims::NOT_BEFORE => $this->now->modify('-20 seconds'),
                RegisteredClaims::EXPIRATION_TIME => $this->now->modify('+60 seconds'),
            ]
        );

        self::assertNull($constraint->assert($token));

        $token = $this->buildToken(
            [
                RegisteredClaims::ISSUED_AT => $this->now,
                RegisteredClaims::NOT_BEFORE => $this->now,
                RegisteredClaims::EXPIRATION_TIME => $this->now->modify('+60 seconds'),
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
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenTokenDoesNotHaveTimeClaims(): void
    {
        $token = $this->buildToken();
        $constraint = new ValidAt($this->now);
        self::assertNull($constraint->assert($token));
    }
}
