<?php

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class RelatedTo implements Constraint
{
    /** @var string */
    private $subject;

    public function __construct($subject)
    {
        $this->subject = $subject;
    }

    public function assert(Token $token)
    {
        if (! $token->isRelatedTo($this->subject)) {
            throw new ConstraintViolation(
                'The token is not related to the expected subject'
            );
        }
    }
}
