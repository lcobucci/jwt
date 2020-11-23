<?php

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class IssuedBy implements Constraint
{
    /** @var string[] */
    private $issuers;

    /** @param list<string> $issuers */
    public function __construct(...$issuers)
    {
        $this->issuers = $issuers;
    }

    public function assert(Token $token)
    {
        if (! $token->hasBeenIssuedBy(...$this->issuers)) {
            throw new ConstraintViolation(
                'The token was not issued by the given issuers'
            );
        }
    }
}
