<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\InvalidToken;

interface Validator
{
    /**
     * @throws InvalidToken
     */
    public function assert(Token $token, Constraint ...$constraints): void;

    public function validate(Token $token, Constraint ...$constraints): bool;
}
