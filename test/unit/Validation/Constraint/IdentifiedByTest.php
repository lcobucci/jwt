<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;

final class IdentifiedByTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldRaiseExceptionWhenIdIsNotSet(): void
    {
        $constraint = new IdentifiedBy('123456');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldRaiseExceptionWhenIdDoesNotMatch(): void
    {
        $constraint = new IdentifiedBy('123456');
        $constraint->assert($this->buildToken([RegisteredClaims::ID => 15]));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldNotRaiseExceptionWhenIdMatches(): void
    {
        $token = $this->buildToken([RegisteredClaims::ID => '123456']);

        $constraint = new IdentifiedBy('123456');
        self::assertNull($constraint->assert($token));
    }
}
