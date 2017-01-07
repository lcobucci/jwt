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
final class AllowedTo implements Constraint
{
    /**
     * @var string
     */
    private $audience;

    public function __construct(string $audience)
    {
        $this->audience = $audience;
    }

    /**
     * {@inheritdoc}
     */
    public function assert(Token $token)
    {
        if (!$token->isAllowedTo($this->audience)) {
            throw new ConstraintViolationException(
                'The token is not allowed to be used by this audience'
            );
        }
    }
}
