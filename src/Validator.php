<?php

namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

interface Validator
{
    /**
     * @throws RequiredConstraintsViolated
     * @throws NoConstraintsGiven
     */
    public function assert(Token $token, Constraint ...$constraints);

    /**
     * @return bool
     *
     * @throws NoConstraintsGiven
     */
    public function validate(Token $token, Constraint ...$constraints);
}
