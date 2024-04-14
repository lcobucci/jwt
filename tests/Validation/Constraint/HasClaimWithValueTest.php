<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\CannotValidateARegisteredClaim;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(HasClaimWithValue::class)]
#[PHPUnit\CoversClass(CannotValidateARegisteredClaim::class)]
#[PHPUnit\UsesClass(Token\DataSet::class)]
#[PHPUnit\UsesClass(Token\Plain::class)]
#[PHPUnit\UsesClass(Token\Signature::class)]
final class HasClaimWithValueTest extends ConstraintTestCase
{
    /** @param non-empty-string $claim */
    #[PHPUnit\Test]
    #[PHPUnit\DataProvider('registeredClaims')]
    public function registeredClaimsCannotBeValidatedUsingThisConstraint(string $claim): void
    {
        $this->expectException(CannotValidateARegisteredClaim::class);
        $this->expectExceptionMessage(
            'The claim "' . $claim . '" is a registered claim, another constraint must be used to validate its value',
        );

        new HasClaimWithValue($claim, 'testing');
    }

    /** @return iterable<non-empty-string, array{non-empty-string}> */
    public static function registeredClaims(): iterable
    {
        foreach (Token\RegisteredClaims::ALL as $claim) {
            yield $claim => [$claim];
        }
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenClaimIsNotSet(): void
    {
        $constraint = new HasClaimWithValue('claimId', 'claimValue');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token does not have the claim "claimId"');

        $constraint->assert($this->buildToken());
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenClaimValueDoesNotMatch(): void
    {
        $constraint = new HasClaimWithValue('claimId', 'claimValue');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The claim "claimId" does not have the expected value');

        $constraint->assert($this->buildToken(['claimId' => 'Some wrong value']));
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $constraint = new HasClaimWithValue('claimId', 'claimValue');

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint->assert($this->createMock(Token::class));
    }

    #[PHPUnit\Test]
    public function assertShouldNotRaiseExceptionWhenClaimMatches(): void
    {
        $token      = $this->buildToken(['claimId' => 'claimValue']);
        $constraint = new HasClaimWithValue('claimId', 'claimValue');

        $constraint->assert($token);
        $this->addToAssertionCount(1);
    }
}
