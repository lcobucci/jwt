<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\PermittedFor */
final class PermittedForTest extends ConstraintTestCase
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
    public function assertShouldRaiseExceptionWhenAudienceIsNotSet(): void
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
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenAudienceValueDoesNotMatch(): void
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
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenAudienceTypeDoesNotMatch(): void
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
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenAudienceMatches(): void
    {
        $token      = $this->buildToken([RegisteredClaims::AUDIENCE => ['aa.com', 'test.com']]);
        $constraint = new PermittedFor('test.com');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
