<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateInterval;
use DateTimeInterface;
use Lcobucci\Clock\Clock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class StrictValidAt implements Constraint
{
    private Clock $clock;
    private DateInterval $leeway;

    public function __construct(Clock $clock, ?DateInterval $leeway = null)
    {
        $this->clock  = $clock;
        $this->leeway = $this->guardLeeway($leeway);
    }

    private function guardLeeway(?DateInterval $leeway): DateInterval
    {
        if ($leeway === null) {
            return new DateInterval('PT0S');
        }

        if ($leeway->invert === 1) {
            throw LeewayCannotBeNegative::create();
        }

        return $leeway;
    }

    public function assert(Token $token): void
    {
        if (! $token instanceof UnencryptedToken) {
            throw new ConstraintViolation('You should pass a plain token');
        }

        $now = $this->clock->now();

        $this->assertIssueTime($token, $now->add($this->leeway));
        $this->assertMinimumTime($token, $now->add($this->leeway));
        $this->assertExpiration($token, $now->sub($this->leeway));
    }

    /** @throws ConstraintViolation */
    private function assertExpiration(UnencryptedToken $token, DateTimeInterface $now): void
    {
        if (! $token->claims()->has(Token\RegisteredClaims::EXPIRATION_TIME)) {
            throw new ConstraintViolation('"Expiration Time" claim missing');
        }

        if ($token->isExpired($now)) {
            throw new ConstraintViolation('The token is expired');
        }
    }

    /** @throws ConstraintViolation */
    private function assertMinimumTime(UnencryptedToken $token, DateTimeInterface $now): void
    {
        if (! $token->claims()->has(Token\RegisteredClaims::NOT_BEFORE)) {
            throw new ConstraintViolation('"Not Before" claim missing');
        }

        if (! $token->isMinimumTimeBefore($now)) {
            throw new ConstraintViolation('The token cannot be used yet');
        }
    }

    /** @throws ConstraintViolation */
    private function assertIssueTime(UnencryptedToken $token, DateTimeInterface $now): void
    {
        if (! $token->claims()->has(Token\RegisteredClaims::ISSUED_AT)) {
            throw new ConstraintViolation('"Issued At" claim missing');
        }

        if (! $token->hasBeenIssuedBefore($now)) {
            throw new ConstraintViolation('The token was issued in the future');
        }
    }
}
