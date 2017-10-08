<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 4.0.0
 */
interface Constraint
{
    /**
     * @param Token $token
     *
     * @throws ConstraintViolationException
     */
    public function assert(Token $token): void;
}
