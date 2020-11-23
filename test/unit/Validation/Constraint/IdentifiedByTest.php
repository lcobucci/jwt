<?php

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\IdentifiedBy
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token
 * @uses \Lcobucci\JWT\Signature
 * @uses \Lcobucci\JWT\Claim\Factory
 */
final class IdentifiedByTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenIdIsNotSet()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not identified with the expected ID');

        $constraint = new IdentifiedBy('123456');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenIdDoesNotMatch()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not identified with the expected ID');

        $constraint = new IdentifiedBy('123456');
        $constraint->assert($this->buildToken([RegisteredClaims::ID => 15]));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldNotRaiseExceptionWhenIdMatches()
    {
        $token = $this->buildToken([RegisteredClaims::ID => '123456']);

        $constraint = new IdentifiedBy('123456');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
