<?php

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\IssuedBy
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token
 * @uses \Lcobucci\JWT\Signature
 * @uses \Lcobucci\JWT\Claim\Factory
 */
final class IssuedByTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenIssuerIsNotSet()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        $constraint = new IssuedBy('test.com', 'test.net');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenIssuerValueDoesNotMatch()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        $constraint = new IssuedBy('test.com', 'test.net');
        $constraint->assert($this->buildToken([RegisteredClaims::ISSUER => 'example.com']));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenIssuerTypeValueDoesNotMatch()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        $constraint = new IssuedBy('test.com', '123');
        $constraint->assert($this->buildToken([RegisteredClaims::ISSUER => 123]));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldNotRaiseExceptionWhenIssuerMatches()
    {
        $token      = $this->buildToken([RegisteredClaims::ISSUER => 'test.com']);
        $constraint = new IssuedBy('test.com', 'test.net');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
