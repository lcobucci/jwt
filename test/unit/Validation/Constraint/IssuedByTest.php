<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\IssuedBy */
final class IssuedByTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenIssuerIsNotSet(): void
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
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenIssuerValueDoesNotMatch(): void
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
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenIssuerTypeValueDoesNotMatch(): void
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
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenIssuerMatches(): void
    {
        $token      = $this->buildToken([RegisteredClaims::ISSUER => 'test.com']);
        $constraint = new IssuedBy('test.com', 'test.net');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
