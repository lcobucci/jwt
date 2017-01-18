<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeImmutable;

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
            'iat' => $currentTime - 20,
            'nbf' => $currentTime - 10,
            'exp' => $currentTime - 10,
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
            'iat' => $currentTime - 20,
            'nbf' => $currentTime + 40,
            'exp' => $currentTime + 60,
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
            'iat' => $currentTime + 20,
            'nbf' => $currentTime + 40,
            'exp' => $currentTime + 60,
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
                'iat' => $currentTime - 40,
                'nbf' => $currentTime - 20,
                'exp' => $currentTime + 60,
            ]
        );

        self::assertNull($constraint->assert($token));

        $token = $this->buildToken(
            [
                'iat' => $currentTime,
                'nbf' => $currentTime,
                'exp' => $currentTime + 60,
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
