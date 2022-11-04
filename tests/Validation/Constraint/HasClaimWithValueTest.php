<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\CannotValidateARegisteredClaim;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @covers \Lcobucci\JWT\Validation\ConstraintViolation
 * @covers \Lcobucci\JWT\Validation\Constraint\HasClaimWithValue
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class HasClaimWithValueTest extends ConstraintTestCase
{
    /**
     * @test
     * @dataProvider registeredClaims
     *
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

    /** @test */
    public function assertShouldRaiseExceptionWhenClaimIsNotSet(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token does not have the claim "claimId"');

        $constraint = new HasClaimWithValue('claimId', 'claimValue');
        $constraint->assert($this->buildToken());
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenClaimValueDoesNotMatch(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The claim "claimId" does not have the expected value');

        $constraint = new HasClaimWithValue('claimId', 'claimValue');
        $constraint->assert($this->buildToken(['claimId' => 'Some wrong value']));
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint = new HasClaimWithValue('claimId', 'claimValue');
        $constraint->assert($this->createMock(Token::class));
    }

    /** @test */
    public function assertShouldNotRaiseExceptionWhenClaimMatches(): void
    {
        $token      = $this->buildToken(['claimId' => 'claimValue']);
        $constraint = new HasClaimWithValue('claimId', 'claimValue');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
