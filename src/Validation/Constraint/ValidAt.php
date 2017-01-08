<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeInterface;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolationException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class ValidAt implements Constraint
{
    /**
     * @var DateTimeInterface
     */
    private $now;

    public function __construct(DateTimeInterface $now)
    {
        $this->now = $now;
    }

    /**
     * {@inheritdoc}
     */
    public function assert(Token $token): void
    {
        $this->assertIssueTime($token);
        $this->assertMinimumTime($token);
        $this->assertExpiration($token);
    }

    /**
     * @throws ConstraintViolationException
     */
    private function assertExpiration(Token $token): void
    {
        if ($token->isExpired($this->now)) {
            throw new ConstraintViolationException('The token is expired');
        }
    }

    /**
     * @throws ConstraintViolationException
     */
    private function assertMinimumTime(Token $token): void
    {
        if (!$token->isMinimumTimeBefore($this->now)) {
            throw new ConstraintViolationException('The token cannot be used yet');
        }
    }

    /**
     * @throws ConstraintViolationException
     */
    private function assertIssueTime(Token $token): void
    {
        if (!$token->hasBeenIssuedBefore($this->now)) {
            throw new ConstraintViolationException('The token was issued in the future');
        }
    }
}
