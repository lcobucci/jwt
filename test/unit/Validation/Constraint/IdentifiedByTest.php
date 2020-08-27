<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\IdentifiedBy */
final class IdentifiedByTest extends ConstraintTestCase
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
    public function assertShouldRaiseExceptionWhenIdIsNotSet(): void
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
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenIdDoesNotMatch(): void
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
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenIdMatches(): void
    {
        $token = $this->buildToken([RegisteredClaims::ID => '123456']);

        $constraint = new IdentifiedBy('123456');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
