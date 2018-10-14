<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;

final class PermittedForTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenAudienceIsNotSet(): void
    {
        $constraint = new PermittedFor('test.com');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenAudienceValueDoesNotMatch(): void
    {
        $constraint = new PermittedFor('test.com');
        $constraint->assert($this->buildToken([RegisteredClaims::AUDIENCE => ['aa.com']]));
    }

    /**
     * @test
     *
     * @expectedException \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenAudienceTypeDoesNotMatch(): void
    {
        $constraint = new PermittedFor('123');
        $constraint->assert($this->buildToken([RegisteredClaims::AUDIENCE => [123]]));
    }

    /**
     * @test
     * @doesNotPerformAssertions
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor::assert
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
    }
}
