<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateInterval;
use DateTimeInterface;
use Lcobucci\Clock\Clock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class ValidAt implements Constraint
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
        $now = $this->clock->now();

        $this->assertIssueTime($token, $now->add($this->leeway));
        $this->assertMinimumTime($token, $now->add($this->leeway));
        $this->assertExpiration($token, $now->sub($this->leeway));
    }

    /** @throws ConstraintViolation */
    private function assertExpiration(Token $token, DateTimeInterface $now): void
    {
        if ($token->isExpired($now)) {
            throw new ConstraintViolation('The token is expired');
        }
    }

    /** @throws ConstraintViolation */
    private function assertMinimumTime(Token $token, DateTimeInterface $now): void
    {
        if (! $token->isMinimumTimeBefore($now)) {
            throw new ConstraintViolation('The token cannot be used yet');
        }
    }

    /** @throws ConstraintViolation */
    private function assertIssueTime(Token $token, DateTimeInterface $now): void
    {
        if (! $token->hasBeenIssuedBefore($now)) {
            throw new ConstraintViolation('The token was issued in the future');
        }
    }
}
