<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use NoDiscard;

interface Validator
{
    /**
     * @throws RequiredConstraintsViolated
     * @throws NoConstraintsGiven
     */
    public function assert(Token $token, Constraint ...$constraints): void;

    /** @throws NoConstraintsGiven */
    #[NoDiscard]
    public function validate(Token $token, Constraint ...$constraints): bool;
}
