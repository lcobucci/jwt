<?php

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\InvalidTokenException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @author Danny Dörfel <danny.dorfel@gmail.com>
 * @author Marco Pivetta <ocramius@gmail.com>
 * @author Henrique Moody <henriquemoody@gmail.com>
 *
 * @since 4.0.0
 */
interface Validator
{
    /**
     * @throws InvalidTokenException
     */
    public function assert(Token $token, Constraint ...$constraints): void;

    public function validate(Token $token, Constraint ...$constraints): bool;
}
