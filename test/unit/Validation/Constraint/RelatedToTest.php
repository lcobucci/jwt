<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

final class RelatedToTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldRaiseExceptionWhenSubjectIsNotSet()
    {
        $constraint = new RelatedTo('user-auth');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldRaiseExceptionWhenSubjectDoesNotMatch()
    {
        $constraint = new RelatedTo('user-auth');
        $constraint->assert($this->buildToken(['sub' => 'password-recovery']));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldNotRaiseExceptionWhenSubjectMatches()
    {
        $token = $this->buildToken(['sub' => 'user-auth']);

        $constraint = new RelatedTo('user-auth');
        self::assertNull($constraint->assert($token));
    }
}
