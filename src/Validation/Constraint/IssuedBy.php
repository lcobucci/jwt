<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class IssuedBy implements Constraint
{
    /**
     * @var string[]
     */
    private $issuers;

    public function __construct(string ...$issuers)
    {
        $this->issuers = $issuers;
    }

    /**
     * {@inheritdoc}
     */
    public function assert(Token $token): void
    {
        if (! $token->hasBeenIssuedBy(...$this->issuers)) {
            throw new ConstraintViolation(
                'The token was not issued by the given issuers'
            );
        }
    }
}
