<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;

interface Constraint
{
    /**
     * @throws ConstraintViolationException
     */
    public function assert(Token $token): void;
}
