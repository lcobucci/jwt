<?php

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\RelatedTo
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token
 * @uses \Lcobucci\JWT\Signature
 * @uses \Lcobucci\JWT\Claim\Factory
 */
final class RelatedToTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenSubjectIsNotSet()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not related to the expected subject');

        $constraint = new RelatedTo('user-auth');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldRaiseExceptionWhenSubjectDoesNotMatch()
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not related to the expected subject');

        $constraint = new RelatedTo('user-auth');
        $constraint->assert($this->buildToken([RegisteredClaims::SUBJECT => 'password-recovery']));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertShouldNotRaiseExceptionWhenSubjectMatches()
    {
        $token      = $this->buildToken([RegisteredClaims::SUBJECT => 'user-auth']);
        $constraint = new RelatedTo('user-auth');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
