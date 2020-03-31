<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\InvalidToken;
use Lcobucci\JWT\Validation\NoConstraintsGiven;

interface Validator
{
    /**
     * @throws InvalidToken
     * @throws NoConstraintsGiven
     */
    public function assert(Token $token, Constraint ...$constraints): void;

    /**
     * @throws NoConstraintsGiven
     */
    public function validate(Token $token, Constraint ...$constraints): bool;
}
