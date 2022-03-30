<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

use function in_array;

final class HasClaimWithValue implements Constraint
{
    private string $claim;

    /** @var mixed */
    private $expectedValue;

    /** @param mixed $expectedValue */
    public function __construct(string $claim, $expectedValue)
    {
        if (in_array($claim, Token\RegisteredClaims::ALL, true)) {
            throw CannotValidateARegisteredClaim::create($claim);
        }

        $this->claim         = $claim;
        $this->expectedValue = $expectedValue;
    }

    public function assert(Token $token): void
    {
        if (! $token instanceof UnencryptedToken) {
            throw new ConstraintViolation('You should pass a plain token');
        }

        $claims = $token->claims();

        if (! $claims->has($this->claim)) {
            throw new ConstraintViolation('The token does not have the claim "' . $this->claim . '"');
        }

        if ($claims->get($this->claim) !== $this->expectedValue) {
            throw new ConstraintViolation('The claim "' . $this->claim . '" does not have the expected value');
        }
    }
}
