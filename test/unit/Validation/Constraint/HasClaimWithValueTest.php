<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\ConstraintViolation;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\HasClaimWithValue */
final class HasClaimWithValueTest extends ConstraintTestCase
{
    /**
     * @test
     * @dataProvider registeredClaims
     *
     * @covers ::__construct
     * @covers \Lcobucci\JWT\Validation\Constraint\CannotValidateARegisteredClaim
     */
    public function registeredClaimsCannotBeValidatedUsingThisConstraint(string $claim): void
    {
        $this->expectException(CannotValidateARegisteredClaim::class);
        $this->expectExceptionMessage(
            'The claim "' . $claim . '" is a registered claim, another constraint must be used to validate its value',
        );

        new HasClaimWithValue($claim, 'testing');
    }

    /** @return iterable<string, array{string}> */
    public function registeredClaims(): iterable
    {
        foreach (Token\RegisteredClaims::ALL as $claim) {
            yield $claim => [$claim];
        }
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     * @covers \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenClaimIsNotSet(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token does not have the claim "claimId"');

        $constraint = new HasClaimWithValue('claimId', 'claimValue');
        $constraint->assert($this->buildToken());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     * @covers \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenClaimValueDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The claim "claimId" does not have the expected value');

        $constraint = new HasClaimWithValue('claimId', 'claimValue');
        $constraint->assert($this->buildToken(['claimId' => 'Some wrong value']));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     * @covers \Lcobucci\JWT\Validation\ConstraintViolation
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint = new HasClaimWithValue('claimId', 'claimValue');
        $constraint->assert($this->createMock(Token::class));
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
    public function assertShouldNotRaiseExceptionWhenClaimMatches(): void
    {
        $token      = $this->buildToken(['claimId' => 'claimValue']);
        $constraint = new HasClaimWithValue('claimId', 'claimValue');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
