<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeInterface;
use Lcobucci\JWT\Validation\ConstraintViolationException;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class NotExpired implements Constraint
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
    public function validate(Token $token)
    {
        if ($token->isExpired($this->now)) {
            throw new ConstraintViolationException('The given token is expired');
        }
    }
}
