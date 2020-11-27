<?php

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\PermittedFor
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token
 * @uses \Lcobucci\JWT\Signature
 * @uses \Lcobucci\JWT\Claim\Factory
 */
final class PermittedForTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenAudienceIsNotSet()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint = new PermittedFor('test.com');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenAudienceValueDoesNotMatch()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint = new PermittedFor('test.com');
        $constraint->assert($this->buildToken([RegisteredClaims::AUDIENCE => ['aa.com']]));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenAudienceTypeDoesNotMatch()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not allowed to be used by this audience');

        $constraint = new PermittedFor('123');
        $constraint->assert($this->buildToken([RegisteredClaims::AUDIENCE => [123]]));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldNotRaiseExceptionWhenAudienceMatches()
    {
        $token      = $this->buildToken([RegisteredClaims::AUDIENCE => ['test.com']]);
        $constraint = new PermittedFor('test.com');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
