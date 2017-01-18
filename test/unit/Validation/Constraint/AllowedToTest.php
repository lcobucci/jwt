<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

final class AllowedToTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldRaiseExceptionWhenAudienceIsNotSet(): void
    {
        $constraint = new AllowedTo('test.com');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldRaiseExceptionWhenAudienceValueDoesNotMatch(): void
    {
        $constraint = new AllowedTo('test.com');
        $constraint->assert($this->buildToken(['aud' => ['aa.com']]));
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolationException
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldRaiseExceptionWhenAudienceTypeDoesNotMatch(): void
    {
        $constraint = new AllowedTo('123');
        $constraint->assert($this->buildToken(['aud' => [123]]));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldNotRaiseExceptionWhenAudienceMatches(): void
    {
        $token = $this->buildToken(['aud' => ['aa.com', 'test.com']]);
        $constraint = new AllowedTo('test.com');

        self::assertNull($constraint->assert($token));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\AllowedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     */
    public function assertShouldNotRaiseExceptionWhenAudienceMatchesAsString(): void
    {
        $token = $this->buildToken(['aud' => 'test.com']);
        $constraint = new AllowedTo('test.com');

        self::assertNull($constraint->assert($token));
    }
}
