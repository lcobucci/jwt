<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class RelatedToTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenSubjectIsNotSet(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not related to the expected subject');

        $constraint = new RelatedTo('user-auth');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenSubjectDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not related to the expected subject');

        $constraint = new RelatedTo('user-auth');
        $constraint->assert($this->buildToken([RegisteredClaims::SUBJECT => 'password-recovery']));
    }

    /**
     * @test
     * @doesNotPerformAssertions
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\RelatedTo::assert
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldNotRaiseExceptionWhenSubjectMatches(): void
    {
        $token      = $this->buildToken([RegisteredClaims::SUBJECT => 'user-auth']);
        $constraint = new RelatedTo('user-auth');

        $constraint->assert($token);
    }
}
