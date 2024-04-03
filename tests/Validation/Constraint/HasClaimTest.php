<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\CannotValidateARegisteredClaim;
use Lcobucci\JWT\Validation\Constraint\HasClaim;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * @covers \Lcobucci\JWT\Validation\ConstraintViolation
 * @covers \Lcobucci\JWT\Validation\Constraint\HasClaim
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class HasClaimTest extends ConstraintTestCase
{
    /**
     * @test
     * @dataProvider registeredClaims
     *
     * @covers \Lcobucci\JWT\Validation\Constraint\CannotValidateARegisteredClaim
     *
     * @param non-empty-string $claim
     */
    public function registeredClaimsCannotBeValidatedUsingThisConstraint(string $claim): void
    {
        $this->expectException(CannotValidateARegisteredClaim::class);
        $this->expectExceptionMessage(
            'The claim "' . $claim . '" is a registered claim, another constraint must be used to validate its value',
        );

        new HasClaim($claim);
    }

    /** @return iterable<non-empty-string, array{non-empty-string}> */
    public static function registeredClaims(): iterable
    {
        foreach (Token\RegisteredClaims::ALL as $claim) {
            yield $claim => [$claim];
        }
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenClaimIsNotSet(): void
    {
        $constraint = new HasClaim('claimId');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token does not have the claim "claimId"');

        $constraint->assert($this->buildToken());
    }

    /** @test */
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $token      = $this->createMock(Token::class);
        $constraint = new HasClaim('claimId');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint->assert($token);
    }

    /** @test */
    public function assertShouldNotRaiseExceptionWhenClaimMatches(): void
    {
        $token      = $this->buildToken(['claimId' => 'claimValue']);
        $constraint = new HasClaim('claimId');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
