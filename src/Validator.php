<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

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
    public function assert(Token $token, Constraint ...$constraints);

    public function validate(Token $token, Constraint ...$constraints): bool;
}
