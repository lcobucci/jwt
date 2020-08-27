<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\RelatedTo */
final class RelatedToTest extends ConstraintTestCase
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
     * @covers ::__construct
     * @covers ::assert
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
     *
     * @covers ::__construct
     * @covers ::assert
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
        $this->addToAssertionCount(1);
    }
}
